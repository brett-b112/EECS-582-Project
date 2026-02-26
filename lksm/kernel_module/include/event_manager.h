#ifndef EVENT_MANAGER_H
#define EVENT_MANAGER_H

#include <linux/types.h>
#include <linux/ktime.h>

/* event types - add new types as detectors are added */
enum photon_event_type {
    PHOTON_EVENT_KPROBE_REG = 1,
    PHOTON_EVENT_SYSCALL_HOOK = 2,
    PHOTON_EVENT_MODULE_HIDDEN = 3,
    PHOTON_EVENT_PROCESS_HIDDEN = 4,
    PHOTON_EVENT_NETWORK_HOOK = 5,
    PHOTON_EVENT_HEARTBEAT = 100,      // periodic keepalive
    PHOTON_EVENT_KEY_ROTATION = 101,   // key change event
};

/* detector IDs - maps to detector array in main.c */
enum photon_detector_id {
    PHOTON_DETECTOR_KPROBE = 1,
    PHOTON_DETECTOR_SYSCALL = 2,
};

/* max event payload size */
#define PHOTON_MAX_EVENT_DATA 512


/* event structure (before encryption) */
struct photon_event {
    u64 sequence_num;              // monotonic counter
    u64 timestamp_ns;              // ktime_get_real_ns()
    u32 event_type;                // photon_event_type
    u32 detector_id;               // photon_detector_id
    u16 data_len;                  // length of data field
    u8  data[PHOTON_MAX_EVENT_DATA]; // variable payload
} __attribute__((packed));


/**
 * event_manager_init - Initialize the event management subsystem
 * 
 * sets up event buffers, crypto, and communication channels
 * 
 * returns: 0 on success, negative error code on failure
 */
int event_manager_init(void);

/**
 * event_manager_exit - Cleanup the event management subsystem
 * 
 * flushes pending events and tears down channels
 */
void event_manager_exit(void);

/**
 * photon_log_event - Log a security event
 * @event_type: type of event (photon_event_type)
 * @detector_id: which detector generated this (photon_detector_id)
 * @data: pointer to event-specific data
 * @data_len: length of data
 * 
 * this function can be called from any detector to log an event.
 * events are automatically encrypted and transmitted to userspace.
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_log_event(u32 event_type, u32 detector_id, 
                     const void *data, u16 data_len);

/**
 * photon_get_sequence - Get current sequence number
 * 
 * useful for debugging and detecting sequence gaps
 * 
 * returns: Current sequence number
 */
u64 photon_get_sequence(void);

/**
 * photon_send_heartbeat - Send a heartbeat event
 * 
 * should be called periodically to prove the module is alive
 * and the communication channel is working
 * 
 * returns: 0 on success, negative error code on failure
 */
int photon_send_heartbeat(void);

#endif /* EVENT_MANAGER_H */