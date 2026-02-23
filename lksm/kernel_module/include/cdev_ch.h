#ifndef CDEV_CHANNEL_H
#define CDEV_CHANNEL_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include "event_manager.h"

/* device name — appears as /dev/photon_ring */
#define PHOTON_RING_DEV_NAME    "photon_ring"
#define PHOTON_RING_CLASS_NAME  "photon_ring"

/*
 * ioctl interface
 *
 * only one ioctl is needed for the simple design: setting the master key.
 * the magic number 0xPR ('P','R' → 0x50, using 0xBE for "Photon Ring BE-am") 
 * is chosen to avoid collision with standard ioctl magic numbers.
 */
#define PHOTON_RING_IOC_MAGIC   0xBE

/*
 * PHOTON_IOC_SET_KEY - provide the 32-byte master key to the kernel module
 *
 * arg: pointer to 32-byte key buffer in userspace
 *
 * returns 0 on success.
 * returns -EEXIST  if the key has already been set (one-time operation).
 * returns -EPERM   if caller does not have CAP_SYS_ADMIN.
 * returns -EFAULT  if the userspace pointer is invalid.
 * returns -EINVAL  if the key length implied by the ioctl is wrong.
 */
#define PHOTON_IOC_SET_KEY  _IOW(PHOTON_RING_IOC_MAGIC, 1, __u8[32])

/*
 * wire frame format written to the ring buffer and read by userspace.
 *
 * every frame is:
 *   [ u32 frame_len ][ photon_frame body of exactly frame_len bytes ]
 *
 * userspace reads the 4-byte header first, then reads exactly frame_len bytes.
 *
 * photon_frame body layout (packed, little-endian):
 *   u64  sequence_num   — plaintext monotonic counter (for gap detection)
 *   u64  rotation_num   — which HKDF session key was used
 *   u8   iv[12]         — AES-GCM initialisation vector
 *   u16  encrypted_len  — length of the encrypted payload (== sizeof photon_event)
 *   u8   auth_tag[16]   — AES-GCM authentication tag
 *   u8   encrypted_data[encrypted_len]  — AES-256-GCM ciphertext of photon_event
 */

/* ring buffer capacity — number of frames that can be queued before drops */
#define PHOTON_RING_BUF_FRAMES  256

/**
 * cdev_channel_init - register the character device
 *
 * allocates a dynamic major number, creates the device class and node
 * under /dev/photon_ring.
 *
 * returns 0 on success, negative error code on failure.
 */
int cdev_channel_init(void);

/**
 * cdev_channel_exit - unregister the character device
 *
 * wakes any sleeping readers, destroys the device class and node,
 * and releases the major number.
 */
void cdev_channel_exit(void);

/**
 * photon_send_encrypted_event - encrypt and enqueue an event for userspace
 * @event: plaintext photon_event to encrypt and deliver
 *
 * encrypts the event with the current session key and pushes the resulting
 * frame into the ring buffer.  A sleeping reader in userspace is woken.
 *
 * if no key has been set yet, the frame is silently dropped (buffering
 * before key exchange is handled by event_manager's existing buffer).
 *
 * returns 0 on success, negative error code on failure.
 */
int photon_send_encrypted_event(struct photon_event *event);

#endif /* CDEV_CHANNEL_H */