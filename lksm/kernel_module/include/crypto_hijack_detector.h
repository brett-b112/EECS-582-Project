#ifndef CRYPTO_HIJACK_DETECTOR_H
#define CRYPTO_HIJACK_DETECTOR_H

#include <linux/ftrace.h>

/*
 * crypto_hijack_detector.h — Photon Ring
 *
 * Detects attempts to register a kernel crypto algorithm under a name
 * that Photon Ring itself relies on for event encryption (see crypto.c):
 *
 *   "gcm(aes)"      — AEAD transform used by photon_encrypt_event()
 *   "aes"           — underlying block cipher
 *   "hmac(sha256)"  — HKDF-Extract/Expand in photon_derive_session_key()
 *   "sha256"        — underlying hash
 *   "ghash"         — GCM's authentication component
 *
 * Threat model
 * ------------
 * The kernel Crypto API resolves crypto_alloc_aead()/crypto_alloc_shash()
 * calls by name + priority lookup against a linked list built by
 * crypto_register_alg().  A rootkit (or anything with the ability to load
 * a module or call this API directly) can register a same-named,
 * higher-priority implementation *after* boot.  Any later
 * crypto_alloc_aead("gcm(aes)", ...) call — including Photon Ring's own,
 * and more importantly the daemon relying on correct encryption — would
 * then silently bind to the attacker's implementation instead of the
 * trusted one.  This is true regardless of whether the legitimate
 * algorithm is built statically into vmlinux or loaded as a module: the
 * registration list is mutable at runtime either way.
 *
 * This detector hooks crypto_register_alg() via ftrace and inspects the
 * cra_name of every registration.  Because Photon Ring's crypto_layer_init()
 * runs once at module load and does not expect further registrations for
 * these primitives afterward, any subsequent registration matching a
 * watched name is treated as unambiguously suspicious.
 *
 * Address resolution
 * ------------------
 * crypto_register_alg is exported (EXPORT_SYMBOL), so its address is taken
 * directly — no kallsyms/kprobe bootstrap needed, same as become_root_detector
 * does for commit_creds.
 *
 * Events
 * ------
 * PHOTON_EVENT_CRYPTO_HIJACK with a crypto_hijack_data payload:
 *   cra_name        — algorithm name being registered (e.g. "gcm(aes)")
 *   cra_driver_name — specific implementation name (e.g. "gcm(aes-generic)")
 *   cra_priority    — priority value; higher wins future lookups
 *   return_addr     — parent_ip, the instruction that called
 *                     crypto_register_alg (cross-ref against kallsyms)
 * severity          — always PHOTON_SEV_CRITICAL
 */

/**
 * crypto_hijack_detector_init - Initialize the crypto registration detector
 *
 * Sets up an ftrace hook on crypto_register_alg() to intercept every
 * algorithm registration and flag any whose cra_name matches a primitive
 * Photon Ring depends on for event encryption.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int crypto_hijack_detector_init(void);

/**
 * crypto_hijack_detector_exit - Tear down the crypto registration detector
 *
 * Removes the ftrace hook and releases all resources.
 */
void crypto_hijack_detector_exit(void);

#endif /* CRYPTO_HIJACK_DETECTOR_H */