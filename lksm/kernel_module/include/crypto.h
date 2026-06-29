#ifndef CRYPTO_LAYER_H
#define CRYPTO_LAYER_H

#include <linux/types.h>
#include "event_manager.h"

struct photon_encrypted_msg;

/* -------------------------------------------------------------------------
 * Crypto configuration
 * -------------------------------------------------------------------------*/
#define PHOTON_KEY_SIZE  32   /* AES-256                    */
#define PHOTON_IV_SIZE   12   /* GCM standard               */
#define PHOTON_TAG_SIZE  16   /* GCM authentication tag     */

/* -------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------*/

/**
 * crypto_layer_init - allocate per-CPU AES-GCM transforms.
 *
 * Allocates one struct crypto_aead per possible CPU.  Keys are NOT installed
 * here; call photon_set_encryption_key() after userspace provides the master
 * key via ioctl.
 *
 * Returns 0 on success, negative error code on failure.
 */
int crypto_layer_init(void);

/**
 * crypto_layer_exit - free per-CPU transforms and securely wipe all keys.
 */
void crypto_layer_exit(void);

/* -------------------------------------------------------------------------
 * Key management
 * -------------------------------------------------------------------------*/

/**
 * photon_has_key - return true if the master key has been installed.
 */
bool photon_has_key(void);

/**
 * photon_set_encryption_key - one-time master key installation.
 * @key: 32-byte key material from userspace ioctl.
 *
 * Stores the master key, derives the rotation-0 session key via HKDF-SHA256,
 * and programs all per-CPU AES-GCM transforms.  May only be called once;
 * subsequent calls are rejected by the ioctl handler with -EEXIST.
 *
 * Returns 0 on success, negative error code on failure.
 */
int photon_set_encryption_key(const u8 *key);

/**
 * photon_rotate_key - derive and install a new session key.
 *
 * Increments the rotation counter, derives the new session key from the
 * master key via HKDF-SHA256, and re-keys all per-CPU transforms.
 * Emits a PHOTON_EVENT_SYSTEM_KEY_ROTATION event so userspace can derive
 * the same new key and decrypt subsequent frames.
 *
 * Returns 0 on success, negative error code on failure.
 */
int photon_rotate_key(void);

/**
 * photon_derive_session_key - derive a session key for a given rotation.
 * @rotation_num: rotation index (0 = initial key).
 * @output_key:   output buffer, must be PHOTON_KEY_SIZE bytes.
 *
 * Both kernel and userspace call this with the same master key and rotation
 * number to independently arrive at the same session key.
 *
 * Caller must NOT hold crypto_mutex — this function takes it internally.
 *
 * Returns 0 on success, negative error code on failure.
 */
int photon_derive_session_key(u64 rotation_num, u8 *output_key);

/**
 * photon_get_rotation_number - return the current key rotation counter.
 */
u64 photon_get_rotation_number(void);

/* -------------------------------------------------------------------------
 * Encryption
 * -------------------------------------------------------------------------*/

/**
 * photon_encrypt_event - encrypt one event with this CPU's AES-GCM transform.
 * @event:   plaintext photon_event to encrypt.
 * @enc_msg: output; caller must have sized encrypted_data[] for
 *           sizeof(struct photon_event) bytes.
 *
 * Must only be called from sleepable context (per-CPU flush kthreads).
 * Uses GFP_KERNEL internally.  No lock is taken on the encrypt path; each
 * CPU uses its own transform exclusively.
 *
 * Returns 0 on success, negative error code on failure.
 */
int photon_encrypt_event(struct photon_event *event,
                         struct photon_encrypted_msg *enc_msg);

/**
 * photon_get_random_iv - fill @iv with PHOTON_IV_SIZE random bytes.
 */
void photon_get_random_iv(u8 *iv);

/* -------------------------------------------------------------------------
 * Test-only decryption — excluded from production builds.
 *
 * Define PHOTON_RING_TESTING at compile time (e.g. ccflags-y += -DPHOTON_RING_TESTING
 * in a test Makefile) to enable.  Never define it in the production Makefile.
 * -------------------------------------------------------------------------*/
#ifdef PHOTON_RING_TESTING
/**
 * photon_decrypt_event - decrypt and authenticate one event (testing only).
 * @enc_msg: encrypted message to decrypt.
 * @event:   output plaintext event.
 *
 * Returns 0 on success, -EBADMSG on authentication failure.
 */
int photon_decrypt_event(struct photon_encrypted_msg *enc_msg,
                         struct photon_event *event);
#endif /* PHOTON_RING_TESTING */

#endif /* CRYPTO_LAYER_H */