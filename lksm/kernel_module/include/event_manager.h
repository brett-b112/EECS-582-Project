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
    PHOTON_EVENT_PRIVESC = 6,
    PHOTON_EVENT_BPF_REG = 7,
    PHOTON_EVENT_STAT_PATH_HIDDEN = 8, // task in scheduler but /proc VFS entry missing
    PHOTON_EVENT_STAT_NLINK_AUDIT = 9, // real inode nlink recorded for nlink-manipulation detection
    PHOTON_EVENT_STAT_PID_AUDIT = 10,  // getpriority PID verified in tasklist (audit trail)
    PHOTON_EVENT_HEARTBEAT = 100,      // periodic keepalive
    PHOTON_EVENT_KEY_ROTATION = 101,   // key change event
};

/* detector IDs - maps to detector array in main.c */
enum photon_detector_id {
    PHOTON_DETECTOR_KPROBE = 1,
    PHOTON_DETECTOR_SYSCALL = 2,
    PHOTON_DETECTOR_STAT = 3,
    PHOTON_DETECTOR_BPF = 4,
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

/* kprobe-specific event data */
struct kprobe_event_data {
    char symbol_name[64];
    unsigned long addr;
    u32 flags;
} __attribute__((packed));

struct becomeroot_event_data {
    char process[64];
    u32 pid; 
} __attribute__((packed));

struct bpf_event_data {
    char bpf_function[64];
    unsigned long addr;
    char process[64];
    u32 pid;
} __attribute__((packed));

/*
 * bpf_hook_event_data - rich payload for PHOTON_EVENT_BPF_REG events
 *
 * emitted by bpf_hook_detector when ftrace_set_filter_ip or
 * register_ftrace_function is intercepted.
 *
 * severity values:
 *   BPF_HOOK_SEV_INFO      - legitimate or unrecognised hook, logged for audit
 *   BPF_HOOK_SEV_SUSPICIOUS - target is on the speculative watchlist
 *   BPF_HOOK_SEV_ALERT     - target matches a confirmed rootkit hook
 *   BPF_HOOK_SEV_CRITICAL  - ops callback lives outside known kernel/module text
 */
#define BPF_HOOK_SEV_INFO       0
#define BPF_HOOK_SEV_SUSPICIOUS 1
#define BPF_HOOK_SEV_ALERT      2
#define BPF_HOOK_SEV_CRITICAL   3
 
/*
 * hook_source values — which kprobe fired this event:
 *   BPF_HOOK_SRC_SET_FILTER   - intercepted at ftrace_set_filter_ip
 *   BPF_HOOK_SRC_REGISTER_FN  - intercepted at register_ftrace_function
 */
#define BPF_HOOK_SRC_SET_FILTER  0
#define BPF_HOOK_SRC_REGISTER_FN 1
 
struct bpf_hook_event_data {
    /* the function being hooked (from ftrace_set_filter_ip arg 1) */
    char     target_symbol[64];      // sprint_symbol_no_offset of target_ip
    unsigned long target_addr;       // raw address passed as the filter ip
 
    /* the ftrace_ops callback that will run when the hook fires */
    char     ops_callback_symbol[64]; // sprint_symbol_no_offset of ops->func;
                                      // starts with "0x" if unresolved/anonymous
    unsigned long ops_callback_addr;  // raw ops->func pointer
 
    /* the process that called ftrace_set_filter_ip / register_ftrace_function */
    char     caller_comm[64];
    u32      caller_pid;
 
    u8       severity;               // BPF_HOOK_SEV_* — set by the detector
    u8       hook_source;            // BPF_HOOK_SRC_* — which kprobe fired
} __attribute__((packed));

struct tcp_hiding_event_data {
    char  hooked_symbol[64];     // name of the tcp/udp function being hooked
    unsigned long hooked_addr;   // resolved address of hooked_symbol
    unsigned long caller_addr;   // ftrace_ops * passed by the rootkit (arg 0)
    char  caller_comm[64];       // current->comm of the registering process
    u32   caller_pid;            // current->pid
} __attribute__((packed));

struct stat_event_data {
    char syscall_name[64];   // name of the intercepted syscall
    char path[64];           // path argument (empty for getpriority)
    char caller_comm[64];    // current->comm of the calling process
    u32  caller_pid;         // current->pid
    u32  target_pid;         // PID from /proc path or getpriority 'who' arg; 0 if N/A
    u32  real_nlink;         // inode->i_nlink from kern_path; 0 if N/A
    u32  flags;              // bitmask: see STAT_FLAG_* below
} __attribute__((packed));

/* Flags for stat_event_data.flags */
#define STAT_FLAG_TASK_EXISTS  (1U << 0) // PID found in kernel task list
#define STAT_FLAG_VFS_MISSING  (1U << 1) // /proc entry absent at VFS level
#define STAT_FLAG_IS_DIR       (1U << 2) // path resolved to a directory

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