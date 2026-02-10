#ifndef PHOTON_RING_ARCH_H
#define PHOTON_RING_ARCH_H

#include <linux/ftrace.h>
#include <linux/ftrace_regs.h>
#include <linux/linkage.h>

/*
 * PHOTON_RING_GET_ARG - portable function argument access from ftrace hooks
 *
 * Wraps ftrace_regs_get_argument() so hook callbacks can retrieve the n-th
 * argument of the traced function without arch-specific register access.
 *
 * @fregs: pointer to struct ftrace_regs passed to the hook callback
 * @n:     zero-based argument index (0 = first argument)
 */
#define PHOTON_RING_GET_ARG(fregs, n) ftrace_regs_get_argument(fregs, n)

/*
 * PHOTON_RING_FTRACE_FLAGS - arch-agnostic ftrace_ops flags
 *
 * FTRACE_OPS_FL_RECURSION is the correct flag when using the ftrace_regs
 * callback API.  The older FTRACE_OPS_FL_SAVE_REGS / FTRACE_OPS_FL_IPMODIFY
 * combination is x86-specific and not available on ARM64.
 */
#define PHOTON_RING_FTRACE_FLAGS FTRACE_OPS_FL_RECURSION

#endif /* PHOTON_RING_ARCH_H */
