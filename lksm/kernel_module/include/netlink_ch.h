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