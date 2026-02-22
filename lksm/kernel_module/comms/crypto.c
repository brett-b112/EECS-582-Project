#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <crypto/aead.h>
#include <crypto/gcm.h>
#include <crypto/hash.h>
#include "../include/crypto.h"
#include "../include/event_manager.h"
#include "../include/netlink_ch.h"

/* crypto state */
static struct crypto_aead *g_tfm = NULL;
static struct crypto_shash *g_hmac_tfm = NULL;  // for HKDF
static u8 g_master_key[PHOTON_KEY_SIZE];         // master key (never rotated)
static u8 g_session_key[PHOTON_KEY_SIZE];        // current session key
static bool g_key_set = false;
static atomic64_t g_rotation_counter = ATOMIC64_INIT(0);
static DEFINE_MUTEX(crypto_mutex);

/* stats */
static atomic64_t g_encryptions = ATOMIC64_INIT(0);
static atomic64_t g_decryptions = ATOMIC64_INIT(0);
static atomic64_t g_key_rotations = ATOMIC64_INIT(0);

/**
 * verify_crypto_transform - verify that crypto transform is valid
 */
static int verify_crypto_transform(void)
{
    if (!g_tfm) {
        printk(KERN_ERR "[PHOTON RING] Crypto transform not initialized\n");
        return -EINVAL;
    }
    
    if (!g_key_set) {
        printk(KERN_WARNING "[PHOTON RING] Encryption key not set\n");
        return -ENOKEY;
    }
    
    return 0;
}

void photon_get_random_iv(u8 *iv)
{
    get_random_bytes(iv, PHOTON_IV_SIZE);
}

u64 photon_get_rotation_number(void)
{
    return atomic64_read(&g_rotation_counter);
}

/**
 * hkdf_extract - HKDF-Extract step (RFC 5869)
 * 
 * PRK = HMAC-Hash(salt, IKM)
 */
static int hkdf_extract(const u8 *salt, size_t salt_len,
                       const u8 *ikm, size_t ikm_len,
                       u8 *prk, size_t prk_len)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret;
    
    // allocate HMAC-SHA256 transform
    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm)) {
        return PTR_ERR(tfm);
    }
    
    // allocate descriptor
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    
    desc->tfm = tfm;
    
    // set key (salt)
    ret = crypto_shash_setkey(tfm, salt, salt_len);
    if (ret)
        goto out;
    
    // initialize hash
    ret = crypto_shash_init(desc);
    if (ret)
        goto out;
    
    // update with IKM
    ret = crypto_shash_update(desc, ikm, ikm_len);
    if (ret)
        goto out;
    
    // finalize to get PRK
    ret = crypto_shash_final(desc, prk);
    
out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

/**
 * hkdf_expand - HKDF-Expand step (RFC 5869)
 * 
 * OKM = first L octets of T(1) | T(2) | T(3) | ...
 * where T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
 */
static int hkdf_expand(const u8 *prk, size_t prk_len,
                      const u8 *info, size_t info_len,
                      u8 *okm, size_t okm_len)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    u8 t[32];  // SHA256 output size
    u8 counter = 1;
    size_t pos = 0;
    int ret;
    
    if (okm_len > 255 * 32) {
        return -EINVAL;  // OKM too long for HKDF-SHA256
    }
    
    // allocate HMAC-SHA256 transform
    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm)) {
        return PTR_ERR(tfm);
    }
    
    // allocate descriptor
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    
    desc->tfm = tfm;
    
    // set key (PRK)
    ret = crypto_shash_setkey(tfm, prk, prk_len);
    if (ret)
        goto out;
    
    memset(t, 0, sizeof(t));
    
    while (pos < okm_len) {
        size_t copy_len;
        
        // initialize hash
        ret = crypto_shash_init(desc);
        if (ret)
            goto out;
        
        // update with T(i-1) if not first iteration
        if (counter > 1) {
            ret = crypto_shash_update(desc, t, 32);
            if (ret)
                goto out;
        }
        
        // update with info
        if (info && info_len > 0) {
            ret = crypto_shash_update(desc, info, info_len);
            if (ret)
                goto out;
        }
        
        // update with counter
        ret = crypto_shash_update(desc, &counter, 1);
        if (ret)
            goto out;
        
        // finalize to get T(i)
        ret = crypto_shash_final(desc, t);
        if (ret)
            goto out;
        
        // copy to output
        copy_len = min_t(size_t, okm_len - pos, 32);
        memcpy(okm + pos, t, copy_len);
        pos += copy_len;
        counter++;
    }
    
    ret = 0;
    
out:
    memzero_explicit(t, sizeof(t));
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

int photon_derive_session_key(u64 rotation_num, u8 *output_key)
{
    u8 prk[32];  // SHA256 output
    u8 info[64];
    size_t info_len;
    int ret;
    
    if (!g_key_set) {
        printk(KERN_ERR "[PHOTON RING] Master key not set\n");
        return -ENOKEY;
    }
    
    // prepare info string: "photon-ring-v1" || rotation_num
    info_len = snprintf(info, sizeof(info), "photon-ring-v1-%llu", rotation_num);
    
    printk(KERN_INFO "[PHOTON RING] Deriving session key for rotation %llu\n", 
           rotation_num);
    
    mutex_lock(&crypto_mutex);
    
    // HKDF-Extract: PRK = HMAC-SHA256(salt=rotation_num, IKM=master_key)
    ret = hkdf_extract((u8 *)&rotation_num, sizeof(rotation_num),
                      g_master_key, PHOTON_KEY_SIZE,
                      prk, sizeof(prk));
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] HKDF-Extract failed: %d\n", ret);
        goto out;
    }
    
    // HKDF-Expand: session_key = HKDF-Expand(PRK, info, L=32)
    ret = hkdf_expand(prk, sizeof(prk), info, info_len,
                     output_key, PHOTON_KEY_SIZE);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] HKDF-Expand failed: %d\n", ret);
        goto out;
    }
    
    printk(KERN_INFO "[PHOTON RING] Session key derived successfully\n");
    
out:
    memzero_explicit(prk, sizeof(prk));
    memzero_explicit(info, sizeof(info));
    mutex_unlock(&crypto_mutex);
    return ret;
}

bool photon_has_key(void)
{
    return g_key_set;
}

int photon_set_encryption_key(const u8 *key)
{
    u8 derived_key[PHOTON_KEY_SIZE];
    int ret;
    
    if (!key) {
        return -EINVAL;
    }
    
    if (!g_tfm) {
        printk(KERN_ERR "[PHOTON RING] Crypto transform not initialized\n");
        return -EINVAL;
    }
    
    printk(KERN_INFO "[PHOTON RING] Setting master key (one-time operation)\n");
    
    mutex_lock(&crypto_mutex);
    
    // store master key (never changes after this)
    memcpy(g_master_key, key, PHOTON_KEY_SIZE);
    g_key_set = true;
    
    mutex_unlock(&crypto_mutex);
    
    // derive initial session key (rotation 0)
    ret = photon_derive_session_key(0, derived_key);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to derive initial session key: %d\n", ret);
        mutex_lock(&crypto_mutex);
        memzero_explicit(g_master_key, PHOTON_KEY_SIZE);
        g_key_set = false;
        mutex_unlock(&crypto_mutex);
        return ret;
    }
    
    mutex_lock(&crypto_mutex);
    
    // set derived session key on transform
    memcpy(g_session_key, derived_key, PHOTON_KEY_SIZE);
    ret = crypto_aead_setkey(g_tfm, g_session_key, PHOTON_KEY_SIZE);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to set key: %d\n", ret);
        memzero_explicit(g_master_key, PHOTON_KEY_SIZE);
        memzero_explicit(g_session_key, PHOTON_KEY_SIZE);
        g_key_set = false;
        goto out;
    }
    
    // set authentication tag size
    ret = crypto_aead_setauthsize(g_tfm, PHOTON_TAG_SIZE);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to set auth size: %d\n", ret);
        memzero_explicit(g_master_key, PHOTON_KEY_SIZE);
        memzero_explicit(g_session_key, PHOTON_KEY_SIZE);
        g_key_set = false;
        goto out;
    }
    
    atomic64_set(&g_rotation_counter, 0);
    
    printk(KERN_INFO "[PHOTON RING] Master key set successfully\n");
    printk(KERN_INFO "[PHOTON RING] Initial session key (rotation 0) active\n");
    
out:
    memzero_explicit(derived_key, PHOTON_KEY_SIZE);
    mutex_unlock(&crypto_mutex);
    return ret;
}

int photon_rotate_key(void)
{
    u8 new_session_key[PHOTON_KEY_SIZE];
    u64 new_rotation;
    int ret;
    
    if (!g_key_set) {
        printk(KERN_ERR "[PHOTON RING] Cannot rotate: master key not set\n");
        return -ENOKEY;
    }
    
    // increment rotation counter
    new_rotation = atomic64_inc_return(&g_rotation_counter);
    
    printk(KERN_INFO "[PHOTON RING] Rotating to session key #%llu\n", new_rotation);
    
    // derive new session key from master key
    ret = photon_derive_session_key(new_rotation, new_session_key);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Key rotation failed: %d\n", ret);
        atomic64_dec(&g_rotation_counter);  // rollback counter
        return ret;
    }
    
    mutex_lock(&crypto_mutex);
    
    // wipe old session key
    memzero_explicit(g_session_key, PHOTON_KEY_SIZE);
    
    // set new session key
    memcpy(g_session_key, new_session_key, PHOTON_KEY_SIZE);
    ret = crypto_aead_setkey(g_tfm, g_session_key, PHOTON_KEY_SIZE);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to set rotated key: %d\n", ret);
        // try to restore previous key
        atomic64_dec(&g_rotation_counter);
        photon_derive_session_key(atomic64_read(&g_rotation_counter), g_session_key);
        crypto_aead_setkey(g_tfm, g_session_key, PHOTON_KEY_SIZE);
        memzero_explicit(new_session_key, PHOTON_KEY_SIZE);
        mutex_unlock(&crypto_mutex);
        return ret;
    }
    
    mutex_unlock(&crypto_mutex);
    memzero_explicit(new_session_key, PHOTON_KEY_SIZE);
    
    printk(KERN_INFO "[PHOTON RING] Key rotation successful (now using rotation #%llu)\n",
           new_rotation);
    
    // send key rotation event to userspace
    // this tells userspace to derive the same new key using rotation number
    {
        struct {
            u64 new_rotation_num;
            u64 timestamp_ns;
        } rotation_event;
        
        rotation_event.new_rotation_num = new_rotation;
        rotation_event.timestamp_ns = ktime_get_real_ns();
        
        // note: this event is encrypted with the OLD key, but includes the new
        // rotation number. Userspace will decrypt this, see the rotation number,
        // and then derive the new key for subsequent messages.
        photon_log_event(PHOTON_EVENT_KEY_ROTATION, 0,
                        &rotation_event, sizeof(rotation_event));
    }
    
    return 0;
}

int photon_encrypt_event(struct photon_event *event, 
                        struct photon_encrypted_msg *enc_msg)
{
    struct aead_request *req = NULL;
    struct scatterlist sg_in, sg_out;
    u8 *plaintext = NULL;
    u8 *ciphertext = NULL;
    size_t plaintext_len;
    size_t ciphertext_len;
    int ret;
    
    ret = verify_crypto_transform();
    if (ret)
        return ret;
    
    plaintext_len = sizeof(struct photon_event);
    ciphertext_len = plaintext_len + PHOTON_TAG_SIZE;
    
    // allocate buffers
    plaintext = kmalloc(plaintext_len, GFP_KERNEL);
    ciphertext = kmalloc(ciphertext_len, GFP_KERNEL);
    if (!plaintext || !ciphertext) {
        ret = -ENOMEM;
        goto out;
    }
    
    // copy event to plaintext buffer
    memcpy(plaintext, event, plaintext_len);
    
    // generate random IV
    photon_get_random_iv(enc_msg->iv);
    
    // allocate AEAD request
    req = aead_request_alloc(g_tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out;
    }
    
    // setup scatter/gather lists
    sg_init_one(&sg_in, plaintext, plaintext_len);
    sg_init_one(&sg_out, ciphertext, ciphertext_len);
    
    // setup AEAD request
    aead_request_set_ad(req, 0);  // no additional authenticated data
    aead_request_set_crypt(req, &sg_in, &sg_out, plaintext_len, enc_msg->iv);
    
    // perform encryption
    mutex_lock(&crypto_mutex);
    ret = crypto_aead_encrypt(req);
    mutex_unlock(&crypto_mutex);
    
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Encryption failed: %d\n", ret);
        goto out;
    }
    
    // fill in encrypted message structure
    enc_msg->sequence_num = event->sequence_num;
    enc_msg->encrypted_len = plaintext_len;
    
    // copy ciphertext (without tag)
    memcpy(enc_msg->encrypted_data, ciphertext, plaintext_len);
    
    // copy authentication tag (last PHOTON_TAG_SIZE bytes of output)
    memcpy(enc_msg->auth_tag, ciphertext + plaintext_len, PHOTON_TAG_SIZE);
    
    atomic64_inc(&g_encryptions);
    
out:
    // clear sensitive data
    if (plaintext) {
        memzero_explicit(plaintext, plaintext_len);
        kfree(plaintext);
    }
    if (ciphertext) {
        memzero_explicit(ciphertext, ciphertext_len);
        kfree(ciphertext);
    }
    if (req) {
        aead_request_free(req);
    }
    
    return ret;
}

int photon_decrypt_event(struct photon_encrypted_msg *enc_msg,
                        struct photon_event *event)
{
    struct aead_request *req = NULL;
    struct scatterlist sg_in, sg_out;
    u8 *ciphertext = NULL;
    u8 *plaintext = NULL;
    size_t ciphertext_len;
    size_t plaintext_len;
    int ret;
    
    ret = verify_crypto_transform();
    if (ret)
        return ret;
    
    plaintext_len = enc_msg->encrypted_len;
    ciphertext_len = plaintext_len + PHOTON_TAG_SIZE;
    
    // allocate buffers
    ciphertext = kmalloc(ciphertext_len, GFP_KERNEL);
    plaintext = kmalloc(plaintext_len, GFP_KERNEL);
    if (!ciphertext || !plaintext) {
        ret = -ENOMEM;
        goto out;
    }
    
    // reconstruct ciphertext (data + tag)
    memcpy(ciphertext, enc_msg->encrypted_data, plaintext_len);
    memcpy(ciphertext + plaintext_len, enc_msg->auth_tag, PHOTON_TAG_SIZE);
    
    // allocate AEAD request
    req = aead_request_alloc(g_tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out;
    }
    
    // setup scatter/gather lists
    sg_init_one(&sg_in, ciphertext, ciphertext_len);
    sg_init_one(&sg_out, plaintext, plaintext_len);
    
    // setup AEAD request
    aead_request_set_ad(req, 0);
    aead_request_set_crypt(req, &sg_in, &sg_out, ciphertext_len, enc_msg->iv);
    
    // perform decryption and authentication
    mutex_lock(&crypto_mutex);
    ret = crypto_aead_decrypt(req);
    mutex_unlock(&crypto_mutex);
    
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Decryption failed (auth error?): %d\n", ret);
        goto out;
    }
    
    // copy decrypted event
    memcpy(event, plaintext, sizeof(struct photon_event));
    
    atomic64_inc(&g_decryptions);
    
out:
    if (ciphertext) {
        memzero_explicit(ciphertext, ciphertext_len);
        kfree(ciphertext);
    }
    if (plaintext) {
        memzero_explicit(plaintext, plaintext_len);
        kfree(plaintext);
    }
    if (req) {
        aead_request_free(req);
    }
    
    return ret;
}

int crypto_layer_init(void)
{
    int ret;

    printk(KERN_INFO "[PHOTON RING] Initializing crypto layer...\n");

    // allocates AES-GCM transform
    g_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(g_tfm)) {
        ret = PTR_ERR(g_tfm);
        printk(KERN_ERR "[PHOTON RING] Failed to allocate GCM transform: %d\n", ret);
        g_tfm = NULL;
        return ret;
    }

    printk(KERN_INFO "[PHOTON RING] AES-GCM transform allocated\n");
    printk(KERN_INFO "[PHOTON RING] Key size: %d bits\n", PHOTON_KEY_SIZE * 8);
    printk(KERN_INFO "[PHOTON RING] IV size: %d bytes\n", PHOTON_IV_SIZE);
    printk(KERN_INFO "[PHOTON RING] Auth tag size: %d bytes\n", PHOTON_TAG_SIZE);
    
    // note: key must be set separately via photon_set_encryption_key()
    printk(KERN_WARNING "[PHOTON RING] Encryption key not yet set - waiting for key exchange\n");

    return 0;
}

void crypto_layer_exit(void)
{
    printk(KERN_INFO "[PHOTON RING] Shutting down crypto layer...\n");
    
    // print statistics
    printk(KERN_INFO "[PHOTON RING] Crypto Statistics:\n");
    printk(KERN_INFO "[PHOTON RING]   Encryptions: %lld\n", 
           atomic64_read(&g_encryptions));
    printk(KERN_INFO "[PHOTON RING]   Decryptions: %lld\n", 
           atomic64_read(&g_decryptions));
    printk(KERN_INFO "[PHOTON RING]   Key rotations: %lld\n", 
           atomic64_read(&g_rotation_counter));
    
    // wipe encryption keys
    if (g_key_set) {
        mutex_lock(&crypto_mutex);
        memzero_explicit(g_master_key, PHOTON_KEY_SIZE);
        memzero_explicit(g_session_key, PHOTON_KEY_SIZE);
        g_key_set = false;
        mutex_unlock(&crypto_mutex);
        printk(KERN_INFO "[PHOTON RING] Master and session keys wiped\n");
    }
    
    // free crypto transform
    if (g_tfm) {
        crypto_free_aead(g_tfm);
        g_tfm = NULL;
        printk(KERN_INFO "[PHOTON RING] Crypto transform freed\n");
    }
    
    printk(KERN_INFO "[PHOTON RING] Crypto layer shut down\n");
}