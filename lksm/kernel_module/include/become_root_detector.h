#ifndef BECOME_ROOT_DETECTOR_H
#define BECOME_ROOT_DETECTOR_H

#include <linux/ftrace.h>

/**
 * become_root_detector_init - Initialize the commit_creds detector
 *
 * Sets up an ftrace hook on commit_creds() to intercept all kernel credential
 * changes.  Each call is inspected for the hallmarks of a rootkit privilege
 * escalation:
 *
 *   1. The calling process was unprivileged (old uid != 0).
 *   2. The new credentials grant full root (new uid == 0).
 *   3. The caller's return address does not belong to a set of known-legitimate
 *      kernel exec-path symbols (apply_creds_elf, __set_current_groups, …).
 *
 * When all three conditions hold the event is logged as PHOTON_EVENT_PRIVESC
 * and the parent_ip (the instruction that called commit_creds) is recorded so
 * userspace can cross-reference against kernel symbol tables.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int become_root_detector_init(void);

/**
 * become_root_detector_exit - Tear down the commit_creds detector
 *
 * Removes the ftrace hook and releases all resources.
 */
void become_root_detector_exit(void);

#endif /* BECOME_ROOT_DETECTOR_H */
