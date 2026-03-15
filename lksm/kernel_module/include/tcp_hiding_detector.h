#ifndef TCP_HIDING_DETECTOR_H
#define TCP_HIDING_DETECTOR_H

#include <linux/ftrace.h>

/**
 * tcp_hiding_detector_init - Initialize the TCP hiding detector
 *
 * Resolves addresses of tcp/udp seq_show and tpacket_rcv, then hooks
 * ftrace_set_filter_ip to catch rootkit attempts to install hooks on them.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tcp_hiding_detector_init(void);

/**
 * tcp_hiding_detector_exit - Cleanup the TCP hiding detector
 *
 * Removes the ftrace hook on ftrace_set_filter_ip.
 */
void tcp_hiding_detector_exit(void);

#endif /* TCP_HIDING_DETECTOR_H */