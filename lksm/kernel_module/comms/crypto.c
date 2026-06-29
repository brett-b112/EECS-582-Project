/*
 * crypto.c — Photon Ring
 *
 * AES-256-GCM encryption layer.
 *
 * Performance design (changes from original)
 * -------------------------------------------
 *
 * 1. Per-CPU AEAD transforms (g_cpu_tfm[])
 *    The original design used a single global struct crypto_aead *g_tfm
 *    protected by a spinlock (crypto_enc_lock).  This serialised all
 *    encrypt calls across every CPU through one lock, negating the
 *    per-CPU parallelism that event_manager provides.
 *
 *    Every possible CPU now gets its own transform allocated at init time.
 *    photon_encrypt_event() grabs the transform for the current CPU via
 *    get_cpu() / put_cpu() — no lock is needed at all on the encrypt path.
 *    Key installation and rotation walk all CPUs under crypto_mutex (a
 *    slow, infrequent path) so every transform stays in sync.
 *
 * 2. Per-CPU pre-allocated workspaces (g_cpu_ws[])
 *    The original photon_encrypt_event() called kmalloc(GFP_ATOMIC) three
 *    times per event: plaintext buffer, ciphertext buffer, aead_request.
 *    Even GFP_ATOMIC allocations cost 1–3 µs each under contention and
 *    require slab spinlocks that cause cache-line bouncing across CPUs.
 *
 *    A struct cpu_crypto_ws is pre-allocated once per CPU at init time.
 *    It embeds:
 *      - a plaintext buffer  (sizeof struct photon_event bytes)
 *      - a ciphertext buffer (plaintext + PHOTON_TAG_SIZE bytes)
 *      - an aead_request     (crypto_aead_reqsize() bytes, flexible tail)
 *    photon_encrypt_event() uses get_cpu() to pin to a CPU, grabs that
 *    CPU's workspace and transform, encrypts, and calls put_cpu() —
 *    zero heap allocations on the hot path.
 *
 *    The workspace is per-CPU, so simultaneous calls on different CPUs
 *    never share any buffer.  A single CPU cannot call photon_encrypt_event
 *    re-entrantly because:
 *      (a) on the fast path the caller holds no lock and is in task context,
 *          so a second call would be a different task on a different CPU;
 *      (b) on the slow path the flush kthread is pinned to its CPU and
 *          drains one event at a time from flush_event_buffer().
 *
 * 3. READ_ONCE / WRITE_ONCE on g_key_set
 *    g_key_set is written under crypto_mutex but read locklessly on the
 *    hot path (photon_has_key(), verify_crypto_transform()).  Without
 *    explicit barrier annotations this is a data race under the kernel
 *    memory model, and on weakly-ordered architectures (ARM64) the reader
 *    could observe stale false after the key is installed, pushing events
 *    onto the slow path unnecessarily.  All reads now use READ_ONCE() and
 *    all writes use WRITE_ONCE() to generate the required barriers.
 *
 * 4. crypto_enc_lock removed
 *    Consequence of (1) + (2): no shared mutable state exists during
 *    encryption, so the spinlock that protected the single global transform
 *    is no longer needed and has been removed entirely.
 */
 
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <crypto/aead.h>
#include <crypto/gcm.h>
#include <crypto/hash.h>
#include "../include/crypto.h"
#include "../include/event_manager.h"
#include "../include/cdev_ch.h"
 
/* -------------------------------------------------------------------------
 * Per-CPU workspace
 *
 * Holds the three buffers that photon_encrypt_event() needs.  Allocated
 * once per CPU in crypto_layer_init(); never freed until crypto_layer_exit().
 *
 * Layout of aead_req_storage[]:
 *   [0 .. sizeof(struct aead_request) - 1]  — struct aead_request header
 *   [sizeof(struct aead_request) ..]        — transform-private ctx
 *   Total size = sizeof(struct aead_request) + crypto_aead_reqsize(tfm)
 *   This is exactly what aead_request_alloc() would kmalloc, so we size
 *   the array at init time once we know reqsize from the allocated tfm.
 * -------------------------------------------------------------------------*/
#define PHOTON_PLAINTEXT_LEN   (sizeof(struct photon_event))
#define PHOTON_CIPHERTEXT_LEN  (PHOTON_PLAINTEXT_LEN + PHOTON_TAG_SIZE)
 
struct cpu_crypto_ws {
    u8                plaintext[PHOTON_PLAINTEXT_LEN];
    u8                ciphertext[PHOTON_CIPHERTEXT_LEN];
    /*
     * aead_req_storage is a flexible-length region sized at init time.
     * We allocate the whole struct via kmalloc with extra bytes appended,
     * so this array is declared with length 0 here and the real storage
     * lives in the kmalloc'd tail.
     */
    u8                aead_req_storage[];
};
 
/*
 * Per-CPU pointers.  NULL until crypto_layer_init() succeeds; freed in
 * crypto_layer_exit().  Using a plain pointer array indexed by CPU rather
 * than DEFINE_PER_CPU avoids the per-CPU section alignment constraints
 * that would prevent embedding the flexible array.
 */
static struct cpu_crypto_ws **g_cpu_ws;    /* [NR_CPUS] array of workspace ptrs */
static struct crypto_aead   **g_cpu_tfm;   /* [NR_CPUS] array of transform ptrs */
 
/* -------------------------------------------------------------------------
 * Key state — written once (or on rotation), read on every encrypt call.
 * All writes are under crypto_mutex; reads use READ_ONCE() for the barrier.
 * -------------------------------------------------------------------------*/
static u8          g_master_key[PHOTON_KEY_SIZE];  /* never rotated */
static u8          g_session_key[PHOTON_KEY_SIZE]; /* current HKDF-derived key */
static bool        g_key_set = false;
static atomic64_t  g_rotation_counter = ATOMIC64_INIT(0);
static DEFINE_MUTEX(crypto_mutex);
 
/* stats */
static atomic64_t g_encryptions  = ATOMIC64_INIT(0);
static atomic64_t g_decryptions  = ATOMIC64_INIT(0);
 
/* -------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------*/
 
void photon_get_random_iv(u8 *iv)
{
    get_random_bytes(iv, PHOTON_IV_SIZE);
}
 
u64 photon_get_rotation_number(void)
{
    return atomic64_read(&g_rotation_counter);
}
 
bool photon_has_key(void)
{
    return READ_ONCE(g_key_set);   /* barrier: see file header note (3) */
}
 
static int verify_crypto_transform(void)
{
    if (!READ_ONCE(g_key_set)) {
        return -ENOKEY;
    }
    return 0;
}
 
/* -------------------------------------------------------------------------
 * HKDF-Extract  (RFC 5869 §2.2)
 *   PRK = HMAC-SHA256(salt, IKM)
 * -------------------------------------------------------------------------*/
static int hkdf_extract(const u8 *salt, size_t salt_len,
                        const u8 *ikm,  size_t ikm_len,
                        u8 *prk,        size_t prk_len)
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    int ret;
 
    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
 
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
 
    desc->tfm = tfm;
 
    ret = crypto_shash_setkey(tfm, salt, salt_len);
    if (ret)
        goto out;
 
    ret = crypto_shash_init(desc);
    if (ret)
        goto out;
 
    ret = crypto_shash_update(desc, ikm, ikm_len);
    if (ret)
        goto out;
 
    ret = crypto_shash_final(desc, prk);
 
out:
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}
 
/* -------------------------------------------------------------------------
 * HKDF-Expand  (RFC 5869 §2.3)
 *   OKM = first L octets of T(1) | T(2) | ...
 *   T(i) = HMAC-SHA256(PRK, T(i-1) | info | i)
 * -------------------------------------------------------------------------*/
static int hkdf_expand(const u8 *prk,  size_t prk_len,
                       const u8 *info, size_t info_len,
                       u8 *okm,        size_t okm_len)
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    u8   t[32];  /* SHA-256 output */
    u8   counter = 1;
    size_t pos = 0;
    int ret;
 
    if (okm_len > 255 * 32)
        return -EINVAL;
 
    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
 
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
 
    desc->tfm = tfm;
 
    ret = crypto_shash_setkey(tfm, prk, prk_len);
    if (ret)
        goto out;
 
    memset(t, 0, sizeof(t));
 
    while (pos < okm_len) {
        size_t copy_len;
 
        ret = crypto_shash_init(desc);
        if (ret)
            goto out;
 
        if (counter > 1) {
            ret = crypto_shash_update(desc, t, 32);
            if (ret)
                goto out;
        }
 
        if (info && info_len > 0) {
            ret = crypto_shash_update(desc, info, info_len);
            if (ret)
                goto out;
        }
 
        ret = crypto_shash_update(desc, &counter, 1);
        if (ret)
            goto out;
 
        ret = crypto_shash_final(desc, t);
        if (ret)
            goto out;
 
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
 
/* -------------------------------------------------------------------------
 * photon_derive_session_key
 *
 * Public: called by photon_set_encryption_key() and photon_rotate_key().
 * Also callable from userspace-facing test code to verify key agreement.
 *
 * Acquires crypto_mutex internally; callers must NOT hold it.
 * -------------------------------------------------------------------------*/
int photon_derive_session_key(u64 rotation_num, u8 *output_key)
{
    u8     prk[32];
    u8     info[64];
    size_t info_len;
    int    ret;
 
    if (!READ_ONCE(g_key_set))
        return -ENOKEY;
 
    info_len = snprintf(info, sizeof(info),
                        "photon-ring-v1-%llu", rotation_num);
 
    printk(KERN_INFO "[PHOTON RING] Deriving session key for rotation %llu\n",
           rotation_num);
 
    mutex_lock(&crypto_mutex);
 
    ret = hkdf_extract((u8 *)&rotation_num, sizeof(rotation_num),
                       g_master_key, PHOTON_KEY_SIZE,
                       prk, sizeof(prk));
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] HKDF-Extract failed: %d\n", ret);
        goto out;
    }
 
    ret = hkdf_expand(prk, sizeof(prk), info, info_len,
                      output_key, PHOTON_KEY_SIZE);
    if (ret)
        printk(KERN_ERR "[PHOTON RING] HKDF-Expand failed: %d\n", ret);
    else
        printk(KERN_INFO "[PHOTON RING] Session key derived successfully\n");
 
out:
    memzero_explicit(prk,  sizeof(prk));
    memzero_explicit(info, sizeof(info));
    mutex_unlock(&crypto_mutex);
    return ret;
}
 
/* -------------------------------------------------------------------------
 * set_key_on_all_transforms
 *
 * Internal helper: apply a derived session key to every per-CPU transform.
 * Must be called under crypto_mutex.  The key is applied to all possible
 * CPUs (not just online ones) so that transforms are ready if a CPU is
 * brought online later.
 * -------------------------------------------------------------------------*/
static int set_key_on_all_transforms(const u8 *key)
{
    int cpu, ret;
 
    for_each_possible_cpu(cpu) {
        if (!g_cpu_tfm[cpu])
            continue;
 
        ret = crypto_aead_setkey(g_cpu_tfm[cpu], key, PHOTON_KEY_SIZE);
        if (ret) {
            printk(KERN_ERR "[PHOTON RING] Failed to set key on CPU%d tfm: %d\n",
                   cpu, ret);
            return ret;
        }
    }
    return 0;
}
 
/* -------------------------------------------------------------------------
 * photon_set_encryption_key
 * -------------------------------------------------------------------------*/
int photon_set_encryption_key(const u8 *key)
{
    u8  derived_key[PHOTON_KEY_SIZE];
    int ret;
 
    if (!key)
        return -EINVAL;
 
    if (!g_cpu_tfm) {
        printk(KERN_ERR "[PHOTON RING] Crypto transforms not initialized\n");
        return -EINVAL;
    }
 
    printk(KERN_INFO "[PHOTON RING] Setting master key (one-time operation)\n");
 
    mutex_lock(&crypto_mutex);
    memcpy(g_master_key, key, PHOTON_KEY_SIZE);
    WRITE_ONCE(g_key_set, true);
    mutex_unlock(&crypto_mutex);
 
    /* Derive initial session key (rotation 0) — acquires mutex internally */
    ret = photon_derive_session_key(0, derived_key);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to derive initial session key: %d\n",
               ret);
        mutex_lock(&crypto_mutex);
        memzero_explicit(g_master_key, PHOTON_KEY_SIZE);
        WRITE_ONCE(g_key_set, false);
        mutex_unlock(&crypto_mutex);
        goto out;
    }
 
    mutex_lock(&crypto_mutex);
 
    memcpy(g_session_key, derived_key, PHOTON_KEY_SIZE);
 
    ret = set_key_on_all_transforms(g_session_key);
    if (ret) {
        memzero_explicit(g_master_key, PHOTON_KEY_SIZE);
        memzero_explicit(g_session_key, PHOTON_KEY_SIZE);
        WRITE_ONCE(g_key_set, false);
        mutex_unlock(&crypto_mutex);
        goto out;
    }
 
    atomic64_set(&g_rotation_counter, 0);
 
    mutex_unlock(&crypto_mutex);
 
    printk(KERN_INFO "[PHOTON RING] Master key set; all CPU transforms keyed\n");
    printk(KERN_INFO "[PHOTON RING] Initial session key (rotation 0) active\n");
 
out:
    memzero_explicit(derived_key, PHOTON_KEY_SIZE);
    return ret;
}
 
/* -------------------------------------------------------------------------
 * photon_rotate_key
 * -------------------------------------------------------------------------*/
int photon_rotate_key(void)
{
    u8  new_session_key[PHOTON_KEY_SIZE];
    u64 new_rotation;
    int ret;
 
    if (!READ_ONCE(g_key_set))
        return -ENOKEY;
 
    new_rotation = atomic64_inc_return(&g_rotation_counter);
 
    printk(KERN_INFO "[PHOTON RING] Rotating to session key #%llu\n",
           new_rotation);
 
    /* photon_derive_session_key acquires crypto_mutex internally */
    ret = photon_derive_session_key(new_rotation, new_session_key);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Key derivation failed on rotation: %d\n",
               ret);
        atomic64_dec(&g_rotation_counter);
        goto out;
    }
 
    mutex_lock(&crypto_mutex);
 
    memzero_explicit(g_session_key, PHOTON_KEY_SIZE);
    memcpy(g_session_key, new_session_key, PHOTON_KEY_SIZE);
 
    ret = set_key_on_all_transforms(g_session_key);
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Failed to apply rotated key: %d\n", ret);
        /*
         * Attempt rollback: re-derive the previous key and re-apply it.
         * If that also fails we leave g_key_set true so events keep flowing
         * rather than silently dropping everything; the failure is logged.
         */
        atomic64_dec(&g_rotation_counter);
        if (!photon_derive_session_key(atomic64_read(&g_rotation_counter),
                                       g_session_key)) {
            set_key_on_all_transforms(g_session_key);
        }
        mutex_unlock(&crypto_mutex);
        goto out;
    }
 
    mutex_unlock(&crypto_mutex);
 
    printk(KERN_INFO "[PHOTON RING] Key rotation successful "
           "(now using rotation #%llu)\n", new_rotation);
 
    {
        struct system_data rot_event;
        rot_event.uptime_ns        = ktime_get_ns();
        rot_event.events_sent      = 0;
        rot_event.events_dropped   = 0;
        rot_event.new_rotation_num = new_rotation;
 
        photon_log_event(PHOTON_EVENT_SYSTEM_KEY_ROTATION, 0,
                         PHOTON_SEV_INFO,
                         &rot_event, sizeof(rot_event));
    }
 
out:
    memzero_explicit(new_session_key, PHOTON_KEY_SIZE);
    return ret;
}
 
/* -------------------------------------------------------------------------
 * photon_encrypt_event — hot path, zero allocations
 *
 * Calling convention
 * ------------------
 * May be called from task context (fast path in photon_log_event) or from
 * the per-CPU flush kthread (slow path).  Both contexts are sleepable, so
 * get_cpu() / put_cpu() are safe.
 *
 * Per-CPU exclusion
 * -----------------
 * get_cpu() disables preemption, guaranteeing that no other task can
 * migrate onto this CPU and grab the same workspace between get_cpu() and
 * put_cpu().  The flush kthread is pinned to its CPU and processes one
 * event at a time, so it cannot re-enter this function on the same CPU.
 * The fast path runs in task context where the scheduler can only switch
 * away at a preemption point — and preemption is disabled by get_cpu().
 * -------------------------------------------------------------------------*/
int photon_encrypt_event(struct photon_event *event,
                         struct photon_encrypted_msg *enc_msg)
{
    struct cpu_crypto_ws *ws;
    struct aead_request  *req;
    struct crypto_aead   *tfm;
    struct scatterlist    sg_in, sg_out;
    int cpu, ret;
 
    ret = verify_crypto_transform();
    if (ret)
        return ret;
 
    /*
     * Pin to a CPU.  Preemption is disabled from here until put_cpu().
     * No sleeping is allowed in this window — but crypto_aead_encrypt()
     * with the software GCM implementation is purely synchronous and
     * does not sleep, so this is safe.
     */
    cpu = get_cpu();
    ws  = g_cpu_ws[cpu];
    tfm = g_cpu_tfm[cpu];
 
    if (unlikely(!ws || !tfm)) {
        put_cpu();
        return -ENODEV;
    }
 
    /* req lives in ws->aead_req_storage; cast to the right type */
    req = (struct aead_request *)ws->aead_req_storage;
 
    /* Copy plaintext into workspace buffer */
    memcpy(ws->plaintext, event, PHOTON_PLAINTEXT_LEN);
 
    /* Fresh random IV for every message */
    photon_get_random_iv(enc_msg->iv);
 
    /* Wire up the AEAD request against our workspace buffers */
    aead_request_set_tfm(req, tfm);
    aead_request_set_callback(req, 0, NULL, NULL);
    sg_init_one(&sg_in,  ws->plaintext,  PHOTON_PLAINTEXT_LEN);
    sg_init_one(&sg_out, ws->ciphertext, PHOTON_CIPHERTEXT_LEN);
    aead_request_set_ad(req, 0);
    aead_request_set_crypt(req, &sg_in, &sg_out, PHOTON_PLAINTEXT_LEN,
                           enc_msg->iv);
 
    /* Encrypt — synchronous, no lock needed: each CPU has its own tfm */
    ret = crypto_aead_encrypt(req);
 
    if (likely(ret == 0)) {
        enc_msg->sequence_num  = event->sequence_num;
        enc_msg->encrypted_len = PHOTON_PLAINTEXT_LEN;
 
        /* ciphertext body (sans tag) */
        memcpy(enc_msg->encrypted_data, ws->ciphertext, PHOTON_PLAINTEXT_LEN);
 
        /* auth tag lives at ciphertext + plaintext_len */
        memcpy(enc_msg->auth_tag,
               ws->ciphertext + PHOTON_PLAINTEXT_LEN,
               PHOTON_TAG_SIZE);
 
        atomic64_inc(&g_encryptions);
    } else {
        printk_ratelimited(KERN_ERR "[PHOTON RING] Encryption failed: %d\n",
                           ret);
    }
 
    /* Wipe the workspace plaintext copy — ciphertext is not sensitive */
    memzero_explicit(ws->plaintext, PHOTON_PLAINTEXT_LEN);
 
    put_cpu();
    return ret;
}
 
/* -------------------------------------------------------------------------
 * photon_decrypt_event — testing / validation only
 *
 * Uses the first CPU's transform for simplicity (this is never on a hot
 * path).  Allocates its own buffers because it may be called from contexts
 * where the per-CPU workspaces are in use.
 * -------------------------------------------------------------------------*/
int photon_decrypt_event(struct photon_encrypted_msg *enc_msg,
                         struct photon_event *event)
{
    struct aead_request *req      = NULL;
    struct scatterlist   sg_in, sg_out;
    u8                  *ciphertext = NULL;
    u8                  *plaintext  = NULL;
    struct crypto_aead  *tfm;
    size_t               ciphertext_len;
    size_t               plaintext_len;
    int                  ret;
 
    ret = verify_crypto_transform();
    if (ret)
        return ret;
 
    /* Use CPU 0's transform; this function is never called on a hot path */
    tfm = g_cpu_tfm[0];
    if (!tfm)
        return -ENODEV;
 
    plaintext_len  = enc_msg->encrypted_len;
    ciphertext_len = plaintext_len + PHOTON_TAG_SIZE;
 
    ciphertext = kmalloc(ciphertext_len, GFP_KERNEL);
    plaintext  = kmalloc(plaintext_len,  GFP_KERNEL);
    if (!ciphertext || !plaintext) {
        ret = -ENOMEM;
        goto out;
    }
 
    memcpy(ciphertext,                  enc_msg->encrypted_data, plaintext_len);
    memcpy(ciphertext + plaintext_len,  enc_msg->auth_tag,       PHOTON_TAG_SIZE);
 
    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out;
    }
 
    sg_init_one(&sg_in,  ciphertext, ciphertext_len);
    sg_init_one(&sg_out, plaintext,  plaintext_len);
    aead_request_set_ad(req, 0);
    aead_request_set_crypt(req, &sg_in, &sg_out, ciphertext_len, enc_msg->iv);
 
    mutex_lock(&crypto_mutex);
    ret = crypto_aead_decrypt(req);
    mutex_unlock(&crypto_mutex);
 
    if (ret) {
        printk(KERN_ERR "[PHOTON RING] Decryption failed (auth error?): %d\n",
               ret);
        goto out;
    }
 
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
    if (req)
        aead_request_free(req);
 
    return ret;
}
 
/* -------------------------------------------------------------------------
 * crypto_layer_init
 *
 * 1. Allocate g_cpu_tfm[] and g_cpu_ws[] pointer arrays (NR_CPUS entries).
 * 2. For each possible CPU:
 *    a. Allocate and configure a struct crypto_aead transform.
 *    b. Allocate a cpu_crypto_ws with aead_req_storage sized to match.
 *       The workspace is allocated as one contiguous kmalloc so the
 *       aead_request + its private context are in the same cache lines.
 * 3. The auth-tag size is set on every transform now; the key itself is
 *    set later by photon_set_encryption_key() when userspace provides it.
 * -------------------------------------------------------------------------*/
int crypto_layer_init(void)
{
    unsigned int reqsize;
    size_t       ws_alloc_size;
    int          cpu, ret;
 
    printk(KERN_INFO "[PHOTON RING] Initializing crypto layer...\n");
 
    /*
     * Allocate the pointer arrays.  kcalloc zero-initialises so any CPU
     * not yet initialised has a NULL pointer that the encrypt path can
     * detect with the unlikely() guard.
     */
    g_cpu_tfm = kcalloc(nr_cpu_ids, sizeof(*g_cpu_tfm), GFP_KERNEL);
    g_cpu_ws  = kcalloc(nr_cpu_ids, sizeof(*g_cpu_ws),  GFP_KERNEL);
    if (!g_cpu_tfm || !g_cpu_ws) {
        ret = -ENOMEM;
        goto err_arrays;
    }
 
    /*
     * We need reqsize before allocating workspaces.  Allocate a temporary
     * transform just to query it, then free.  All transforms for the same
     * algorithm have the same reqsize, so querying one is sufficient.
     */
    {
        struct crypto_aead *probe = crypto_alloc_aead("gcm(aes)", 0, 0);
        if (IS_ERR(probe)) {
            ret = PTR_ERR(probe);
            printk(KERN_ERR "[PHOTON RING] Failed to probe GCM reqsize: %d\n",
                   ret);
            goto err_arrays;
        }
        reqsize = crypto_aead_reqsize(probe);
        crypto_free_aead(probe);
    }
 
    ws_alloc_size = sizeof(struct cpu_crypto_ws)
                    + sizeof(struct aead_request)
                    + reqsize;
 
    printk(KERN_INFO "[PHOTON RING] AES-GCM reqsize=%u  workspace=%zu B per CPU\n",
           reqsize, ws_alloc_size);
 
    for_each_possible_cpu(cpu) {
        struct crypto_aead    *tfm;
        struct cpu_crypto_ws  *ws;
 
        /* ---- transform ---- */
        tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
        if (IS_ERR(tfm)) {
            ret = PTR_ERR(tfm);
            printk(KERN_ERR "[PHOTON RING] Failed to alloc transform CPU%d: %d\n",
                   cpu, ret);
            goto err_per_cpu;
        }
 
        ret = crypto_aead_setauthsize(tfm, PHOTON_TAG_SIZE);
        if (ret) {
            printk(KERN_ERR "[PHOTON RING] Failed to set authsize CPU%d: %d\n",
                   cpu, ret);
            crypto_free_aead(tfm);
            goto err_per_cpu;
        }
 
        g_cpu_tfm[cpu] = tfm;
 
        /* ---- workspace ---- */
        ws = kmalloc(ws_alloc_size, GFP_KERNEL);
        if (!ws) {
            ret = -ENOMEM;
            printk(KERN_ERR "[PHOTON RING] Failed to alloc workspace CPU%d\n",
                   cpu);
            goto err_per_cpu;
        }
        memset(ws, 0, ws_alloc_size);
        g_cpu_ws[cpu] = ws;
    }
 
    printk(KERN_INFO "[PHOTON RING] Crypto layer ready: %d transform(s), "
           "key size %d bits, IV %d B, tag %d B\n",
           num_possible_cpus(),
           PHOTON_KEY_SIZE * 8, PHOTON_IV_SIZE, PHOTON_TAG_SIZE);
    printk(KERN_WARNING
           "[PHOTON RING] Encryption key not yet set — waiting for key exchange\n");
    return 0;
 
err_per_cpu:
    for_each_possible_cpu(cpu) {
        if (g_cpu_tfm[cpu]) {
            crypto_free_aead(g_cpu_tfm[cpu]);
            g_cpu_tfm[cpu] = NULL;
        }
        if (g_cpu_ws[cpu]) {
            memzero_explicit(g_cpu_ws[cpu], ws_alloc_size);
            kfree(g_cpu_ws[cpu]);
            g_cpu_ws[cpu] = NULL;
        }
    }
 
err_arrays:
    kfree(g_cpu_tfm);
    kfree(g_cpu_ws);
    g_cpu_tfm = NULL;
    g_cpu_ws  = NULL;
    return ret;
}
 
/* -------------------------------------------------------------------------
 * crypto_layer_exit
 * -------------------------------------------------------------------------*/
void crypto_layer_exit(void)
{
    int cpu;
 
    printk(KERN_INFO "[PHOTON RING] Shutting down crypto layer...\n");
 
    printk(KERN_INFO "[PHOTON RING] Crypto statistics: "
           "encryptions=%lld  decryptions=%lld  rotations=%lld\n",
           atomic64_read(&g_encryptions),
           atomic64_read(&g_decryptions),
           atomic64_read(&g_rotation_counter));
 
    /* Wipe key material first, before freeing transforms */
    if (READ_ONCE(g_key_set)) {
        mutex_lock(&crypto_mutex);
        memzero_explicit(g_master_key,  PHOTON_KEY_SIZE);
        memzero_explicit(g_session_key, PHOTON_KEY_SIZE);
        WRITE_ONCE(g_key_set, false);
        mutex_unlock(&crypto_mutex);
        printk(KERN_INFO "[PHOTON RING] Master and session keys wiped\n");
    }
 
    if (g_cpu_tfm && g_cpu_ws) {
        /*
         * Compute ws_alloc_size again to correctly zero workspace memory.
         * We cannot use the saved reqsize here (it's a local in init), so
         * re-derive it from any live transform we still hold.
         */
        size_t ws_alloc_size = 0;
 
        for_each_possible_cpu(cpu) {
            if (g_cpu_tfm[cpu]) {
                ws_alloc_size = sizeof(struct cpu_crypto_ws)
                                + sizeof(struct aead_request)
                                + crypto_aead_reqsize(g_cpu_tfm[cpu]);
                break;
            }
        }
 
        for_each_possible_cpu(cpu) {
            if (g_cpu_ws[cpu]) {
                if (ws_alloc_size)
                    memzero_explicit(g_cpu_ws[cpu], ws_alloc_size);
                kfree(g_cpu_ws[cpu]);
                g_cpu_ws[cpu] = NULL;
            }
            if (g_cpu_tfm[cpu]) {
                crypto_free_aead(g_cpu_tfm[cpu]);
                g_cpu_tfm[cpu] = NULL;
            }
        }
 
        kfree(g_cpu_ws);
        kfree(g_cpu_tfm);
        g_cpu_ws  = NULL;
        g_cpu_tfm = NULL;
    }
 
    printk(KERN_INFO "[PHOTON RING] Crypto layer shut down\n");
}