#ifndef EVENT_MANAGER_H
#define EVENT_MANAGER_H

#include <linux/types.h>
#include <linux/ktime.h>

/* =========================================================================
 * Severity levels — stored in photon_event.severity (envelope field).
 *
 * Promoting severity to the envelope means the userspace daemon and
 * Elasticsearch can triage and range-filter events without decrypting or
 * deserialising the payload at all.
 *
 *   PHOTON_SEV_INFO       — internal / housekeeping (heartbeat, key rotation)
 *   PHOTON_SEV_SUSPICIOUS — watchlisted symbol touched; needs correlation
 *   PHOTON_SEV_ALERT      — strong indicator; likely malicious
 *   PHOTON_SEV_CRITICAL   — unambiguously hostile (anon handler, direct patch,
 *                            uid escalation outside known-good call stack)
 * ========================================================================= */
#define PHOTON_SEV_INFO       0
#define PHOTON_SEV_SUSPICIOUS 1
#define PHOTON_SEV_ALERT      2
#define PHOTON_SEV_CRITICAL   3

/* =========================================================================
 * Event types — namespaced dot-strings mapped to u8 constants.
 *
 * The u8 wire value is what travels inside the encrypted frame.
 * The userspace daemon translates these to their string equivalents
 * ("probe.kprobe", "ftrace.hook", etc.) before indexing into Elasticsearch
 * so that KQL queries and Kibana dashboards are self-documenting.
 *
 * Naming convention:  <category>.<subtype>
 *   probe.*      — kprobe / kretprobe / kallsyms registration events
 *   ftrace.*     — ftrace bypass-path events (set_filter, modify_direct)
 *   privesc.*    — credential / privilege escalation events
 *   hiding.*     — process / network / filesystem hiding events
 *   system.*     — internal module housekeeping
 * ========================================================================= */
enum photon_event_type {
    /* probe category */
    PHOTON_EVENT_PROBE_KPROBE    = 1,   /* "probe.kprobe"    — kprobe_detector       */
    PHOTON_EVENT_PROBE_KRETPROBE = 2,   /* "probe.kretprobe" — kretprobe_detector    */
    PHOTON_EVENT_PROBE_KALLSYMS  = 3,   /* "probe.kallsyms"  — kallsyms_detector     */

    /* ftrace category */
    PHOTON_EVENT_FTRACE_HOOK     = 4,   /* "ftrace.hook"     — ftrace_direct_detector */

    /* privilege escalation category */
    PHOTON_EVENT_PRIVESC_UID     = 5,   /* "privesc.uid"     — become_root_detector  */

    /* hiding category */
    PHOTON_EVENT_HIDING_PROCESS  = 6,   /* "hiding.process"  — stat / proc detectors */
    PHOTON_EVENT_HIDING_NETWORK  = 7,   /* "hiding.network"  — tcp_hiding_detector   */

    /* system category */
    PHOTON_EVENT_SYSTEM_HEARTBEAT    = 100,  /* "system.heartbeat"    */
    PHOTON_EVENT_SYSTEM_KEY_ROTATION = 101,  /* "system.key_rotation" */
};

/* =========================================================================
 * Detector IDs — map to the detectors[] array in main.c.
 * ========================================================================= */
enum photon_detector_id {
    PHOTON_DETECTOR_KPROBE    = 1,
    PHOTON_DETECTOR_KRETPROBE = 2,
    PHOTON_DETECTOR_STAT      = 3,
    PHOTON_DETECTOR_BPF       = 4,
    PHOTON_DETECTOR_FTRACE    = 5,
    PHOTON_DETECTOR_PRIVESC   = 6,
};

/* =========================================================================
 * Maximum payload size.
 *
 * Reduced from 512 to 256: common caller fields (pid/comm) moved to the
 * envelope, so payload structs carry only detector-specific data.
 * ========================================================================= */
#define PHOTON_MAX_EVENT_DATA 256

/* =========================================================================
 * photon_event — plaintext envelope (encrypted as a unit by crypto.c).
 *
 * Fields present in every event regardless of type:
 *
 *   sequence_num  — monotonic u64; gap detection in userspace
 *   timestamp_ns  — ktime_get_real_ns(); userspace converts to @timestamp
 *   event_type    — photon_event_type wire value
 *   detector_id   — photon_detector_id
 *   severity      — PHOTON_SEV_* (0-3); top-level ES field, enables range
 *                   filters without touching the payload
 *   caller_pid    — current->pid of the task that triggered the event;
 *                   captured inside photon_log_event(), not by the detector
 *   caller_comm   — current->comm (task name, NUL-padded to 16 bytes);
 *                   captured inside photon_log_event()
 *   data_len      — valid bytes in data[]
 *   data[]        — typed payload (one of the structs below)
 * ========================================================================= */
struct photon_event {
    u64  sequence_num;
    u64  timestamp_ns;
    u32  event_type;
    u32  detector_id;
    u8   severity;          /* PHOTON_SEV_* — promoted from per-payload field */
    u8   _pad[3];           /* keep data[] 4-byte aligned                     */
    u32  caller_pid;        /* current->pid — promoted from payload structs   */
    char caller_comm[16];   /* current->comm — promoted from payload structs  */
    u16  data_len;
    u8   data[PHOTON_MAX_EVENT_DATA];
} __attribute__((packed));

/* =========================================================================
 * Payload struct 1 — probe_hook_data
 *
 * Used by:
 *   PHOTON_EVENT_PROBE_KPROBE    (kprobe_detector)
 *   PHOTON_EVENT_PROBE_KRETPROBE (kretprobe_detector)
 *   PHOTON_EVENT_PROBE_KALLSYMS  (kallsyms_detector)
 *
 * Fields that do not apply to a given sub-type are zeroed:
 *   kprobe path       — symbol_name, target_addr, flags
 *   kretprobe path    — all of the above + handler_addr, entry_addr,
 *                       maxactive, batch_count
 *   kallsyms path     — symbol_name, target_addr (= caller IP), flags
 *
 * Flags bitmask (PROBE_FLAG_*):
 *   PROBE_FLAG_WATCHLISTED   — symbol is on photon_watchlist
 *   PROBE_FLAG_ANON_HANDLER  — handler address outside the symbol table
 *   PROBE_FLAG_HIGH_ACTIVE   — maxactive above threshold (kretprobe only)
 *   PROBE_FLAG_BATCH         — arrived via register_kprobes() batch call
 * ========================================================================= */
#define PROBE_FLAG_WATCHLISTED  0x01u
#define PROBE_FLAG_ANON_HANDLER 0x02u
#define PROBE_FLAG_HIGH_ACTIVE  0x04u
#define PROBE_FLAG_BATCH        0x08u

struct probe_hook_data {
    char          symbol_name[64];  /* target symbol or lookup name            */
    unsigned long target_addr;      /* resolved address of probe target        */
    unsigned long handler_addr;     /* kretprobe return handler (0 for kprobe) */
    unsigned long entry_addr;       /* kretprobe entry handler (0 for kprobe)  */
    int           maxactive;        /* kretprobe maxactive  (0 for kprobe)     */
    int           batch_count;      /* 1 for single; N for register_kprobes()  */
    u32           flags;            /* PROBE_FLAG_* bitmask                    */
} __attribute__((packed));

/* =========================================================================
 * Payload struct 2 — ftrace_hook_data
 *
 * Used by:
 *   PHOTON_EVENT_FTRACE_HOOK (ftrace_direct_detector)
 *
 * Covers three hook sources:
 *   FTRACE_HOOK_SRC_SET_FILTER   — ftrace_set_filter (glob API)
 *   FTRACE_HOOK_SRC_SET_NOTRACE  — ftrace_set_notrace (glob API)
 *   FTRACE_HOOK_SRC_MODIFY       — modify_ftrace_direct (direct patching)
 *
 * severity is NOT in this struct; it lives in the envelope.
 * ========================================================================= */
#define FTRACE_HOOK_SRC_SET_FILTER  0
#define FTRACE_HOOK_SRC_SET_NOTRACE 1
#define FTRACE_HOOK_SRC_MODIFY      2

struct ftrace_hook_data {
    char          target_symbol[64];   /* symbol being hooked / patched        */
    unsigned long target_addr;         /* raw address of the hook target       */
    char          new_addr_symbol[64]; /* resolved name of callback / dest     */
    unsigned long new_addr;            /* raw callback / new-destination addr  */
    char          filter_pattern[64];  /* glob pattern (SET_FILTER path only)  */
    u8            hook_source;         /* FTRACE_HOOK_SRC_*                    */
} __attribute__((packed));

/* =========================================================================
 * Payload struct 3 — privesc_data
 *
 * Used by:
 *   PHOTON_EVENT_PRIVESC_UID (become_root_detector)
 * ========================================================================= */
struct privesc_data {
    u32           old_uid;       /* uid before commit_creds()                  */
    u32           new_uid;       /* uid after  commit_creds() (== 0)           */
    unsigned long return_addr;   /* parent_ip — instruction that called        */
                                 /*   commit_creds; cross-ref against kallsyms */
} __attribute__((packed));

/* =========================================================================
 * Payload struct 4 — hidden_entity_data
 *
 * Used by:
 *   PHOTON_EVENT_HIDING_PROCESS (hiding_stat / proc detectors)
 *   PHOTON_EVENT_HIDING_NETWORK (tcp_hiding_detector)
 *
 * entity_type distinguishes the two sub-cases:
 *   HIDDEN_ENTITY_PROCESS  — PID visible in task list but missing from /proc
 *   HIDDEN_ENTITY_NETWORK  — TCP/UDP seq_show hook intercepted
 *
 * Flags (HIDDEN_FLAG_*):
 *   HIDDEN_FLAG_TASK_EXISTS — PID confirmed in kernel task list
 *   HIDDEN_FLAG_VFS_MISSING — /proc entry absent at VFS level
 *   HIDDEN_FLAG_IS_DIR      — path resolved to a directory
 * ========================================================================= */
#define HIDDEN_ENTITY_PROCESS 0
#define HIDDEN_ENTITY_NETWORK 1

#define HIDDEN_FLAG_TASK_EXISTS 0x01u
#define HIDDEN_FLAG_VFS_MISSING 0x02u
#define HIDDEN_FLAG_IS_DIR      0x04u

struct hidden_entity_data {
    u8            entity_type;      /* HIDDEN_ENTITY_*                         */
    u32           target_pid;       /* hidden PID (0 if N/A)                   */
    char          target_path[64];  /* /proc path or hooked symbol name        */
    char          syscall_name[32]; /* intercepted syscall (process path only) */
    unsigned long hooked_addr;      /* resolved addr of hooked symbol (net)    */
    u32           real_nlink;       /* inode->i_nlink from kern_path           */
    u32           flags;            /* HIDDEN_FLAG_* bitmask                   */
} __attribute__((packed));

/* =========================================================================
 * Payload struct 5 — system_data
 *
 * Used by:
 *   PHOTON_EVENT_SYSTEM_HEARTBEAT
 *   PHOTON_EVENT_SYSTEM_KEY_ROTATION
 *
 * For heartbeats, new_rotation_num is 0.
 * For key rotation events, new_rotation_num carries the new counter value
 * and the sent/dropped fields snapshot module state at rotation time.
 * ========================================================================= */
struct system_data {
    u64 uptime_ns;
    u64 events_sent;
    u64 events_dropped;
    u64 new_rotation_num;  /* 0 for heartbeat, >0 for key_rotation            */
} __attribute__((packed));

/* =========================================================================
 * Public API
 * ========================================================================= */

/**
 * event_manager_init - initialise per-CPU event buffers, crypto subsystem,
 *                      and the cdev channel.
 * Returns 0 on success, negative error code on failure.
 */
int event_manager_init(void);

/**
 * event_manager_exit - flush pending events and tear down all subsystems.
 */
void event_manager_exit(void);

/**
 * photon_log_event - encrypt and deliver one security event to userspace.
 *
 * @event_type:  photon_event_type constant (e.g. PHOTON_EVENT_PROBE_KPROBE)
 * @detector_id: photon_detector_id constant
 * @severity:    PHOTON_SEV_* (0-3) — caller sets threat level
 * @data:        pointer to the typed payload struct
 * @data_len:    sizeof the payload struct
 *
 * caller_pid and caller_comm are captured from current inside this function;
 * detectors do not need to include them in their payload structs.
 *
 * Returns 0 on success, negative error code on failure.
 */
int photon_log_event(u32 event_type, u32 detector_id, u8 severity,
                     const void *data, u16 data_len);

/**
 * photon_get_sequence - return the current monotonic sequence counter.
 */
u64 photon_get_sequence(void);

/**
 * photon_send_heartbeat - emit a system.heartbeat event.
 */
int photon_send_heartbeat(void);

#endif /* EVENT_MANAGER_H */