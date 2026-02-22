#ifndef NETLINK_CHANNEL_H
#define NETLINK_CHANNEL_H

#include <linux/types.h>
#include "event_manager.h"

/* generic Netlink family name and version */
#define PHOTON_RING_GENL_NAME "photon_ring"
#define PHOTON_RING_GENL_VERSION  1

/* multicast group name */
#define PHOTON_RING_MCGRP_NAME "events"

/* generic Netlink commands */
enum photon_genl_commands {
    PHOTON_CMD_UNSPEC = 0,
    PHOTON_CMD_EVENT, // send encrypted event to userspace
    PHOTON_CMD_REGISTER, // userspace registers as listener
    PHOTON_CMD_KEY_EXCHANGE, // key establishment protocol
    PHOTON_CMD_HEARTBEAT, // heartbeat/keepalive
    __PHOTON_CMD_MAX,
};

#define PHOTON_ATTR_MAX (__PHOTON_ATTR_MAX - 1)

/* generic Netlink attributes */
enum photon_genl_attributes {
    PHOTON_ATTR_UNSPEC = 0,
    PHOTON_ATTR_ENCRYPTED_DATA, // encrypted event payload
    PHOTON_ATTR_IV,             // GCM initialization vector
    PHOTON_ATTR_AUTH_TAG,       // GCM authentication tag
    PHOTON_ATTR_SEQUENCE,       // sequence number
    PHOTON_ATTR_ROTATION_NUM,   // key rotation number
    PHOTON_ATTR_TIMESTAMP,      // event timestamp
    PHOTON_ATTR_PUBLIC_KEY,     // public key for key exchange
    PHOTON_ATTR_ENCRYPTED_KEY,  // encrypted session key
    __PHOTON_ATTR_MAX,
};

/* max message size */
#define PHOTON_MAX_MSG_SIZE 2048

/* encrypted message structure */
struct photon_encrypted_msg {
    u64 sequence_num; // plaintext for ordering
    u64 rotation_num; // key rotation number
    u8 iv[12]; // GCM initialization vector
    u16 encrypted_len; // length of encrypted data
    u8 auth_tag[16]; // GCM authentication tag
    u8 encrypted_data[]; // encrypted photon_event
} __attribute__((packed));

/**
 * netlink_channel_init - initialize the netlink communication channel
 * 
 * registers generic netlink family and multicast groups
 * 
 * returns: 0 on success, negative error code on failure
 */
int netlink_channel_init(void);

/**
 * netlink_channel_exit - cleanup the netlink channel
 * 
 * unregisters generic netlink family
 */
void netlink_channel_exit(void);

/**
 * photon_send_encrypted_event - send an encrypted event via netlink
 * @event: pointer to (encrypted) event structure
 * 
 * encrypts the event and sends it to all registered 
 * userspace listeners via netlink multicast
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_send_encrypted_event(struct photon_event *event);

/**
 * photon_verify_listener - verify the credentials of a netlink listener
 * @portid: netlink port ID of the listener
 * 
 * verifies that the listener process is authorized to receive events.
 * Checks process credentials, executable path, etc.
 * 
 * returns: 0 if verified, negative error code otherwise
 */
int photon_verify_listener(u32 portid);

#endif /* NETLINK_CHANNEL_H */