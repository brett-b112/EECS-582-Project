#ifndef CRYPTO_LAYER_H
#define CRYPTO_LAYER_H

#include <linux/types.h>
#include "event_manager.h"

struct photon_encrypted_msg;

/* crypto config */
#define PHOTON_KEY_SIZE 32 // AES-256
#define PHOTON_IV_SIZE 12 // GCM standard
#define PHOTON_TAG_SIZE 16 // GCM authentication tag

/** 
 * crypto_layer_init - initialize the cryptographic subsystem
 * 
 * allocates crypto transforms and initializes key management
 * 
 * returns: 0 on success, negative error code on failure
 */
int crypto_layer_init(void);

/**
 * crypto_layer_exit - cleanup the cryptographic subsystem
 * 
 * frees crypto transforms and securely wipes keys
 */
void crypto_layer_exit(void);

/**
 * photon_has_key - Check if encryption key is set
 * 
 * returns: true if key is set, false otherwise
 */
bool photon_has_key(void);

/** 
 * photon_encrypt_event - encrypt an event using AES-GCM
 * @event: pointer to plaintext event
 * @enc_msg: pointer to output encrypted message structure
 * 
 * encrypts the event using AES-256-GCM and fills the encrypted
 * message structure with ciphertext, IV, and authentication tag.
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_encrypt_event(struct photon_event *event,
                        struct photon_encrypted_msg *enc_msg);

/**
 * photon_decrypt_event - decrypt an event (for testing/validation)
 * @enc_msg: pointer to encrypted message
 * @event: pointer to output plaintext event
 * 
 * decrypts and verifies the event. Used primarily for testing.
 * 
 * DO NOT LET THIS FUNCTION MAKE IT INTO PRODUCTION BUILDS!!!!!!
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_decrypt_event(struct photon_encrypted_msg *enc_msg,
                        struct photon_event *event);

/**
 * photon_set_encryption_key - set the encryption key
 * @key: pointer to key material (must be PHOTON_KEY_SIZE bytes)
 * 
 * sets the key used for event encryption
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_set_encryption_key(const u8 *key);

/**
 * photon_rotate_key - derive and rotate to a new encryption key
 * 
 * derives a new key from the master key and current rotation count
 * using HKDF
 * 
 * both kernel and userspace independently derive the same keys using:
 * - shared master key (established at init)
 * - rotation counter (deterministic sequence)
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_rotate_key(void);

/**
 * photon_get_random_iv - generate a random IV for encryption
 * @iv: buffer to store IV (must be PHOTON_IV_SIZE bytes)
 */
void photon_get_random_iv(u8 *iv);

/**
 * photon_derive_session_key - derive a session key from master key
 * @rotation_num: rotation counter (0 for initial key, 1+ for rotations)
 * @output_key: buffer to store derived key (PHOTON_KEY_SIZE bytes)
 * 
 * uses HKDF-SHA256 to derive session keys from the master key.
 * Both kernel and userspace use the same function to derive identical keys.
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_derive_session_key(u64 rotation_num, u8 *output_key);

/**
 * photon_get_rotation_number - get current key rotation number
 * 
 * returns: Current rotation counter
 */
u64 photon_get_rotation_number(void);

#endif /* CRYPTO_LAYER_H */