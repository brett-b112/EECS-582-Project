#ifndef PHOTON_RING_ARCH_H
#define PHOTON_RING_ARCH_H

#include <linux/ftrace.h>
#include <linux/version.h>
#include <asm/ptrace.h>

/*
 * Architecture-portable macros for Photon Ring
 *
 * Two abstraction layers are provided:
 *
 * 1. PHOTON_RING_GET_ARG(fregs, n) — for ftrace-based detectors
 *    Extracts the nth function argument from ftrace_regs.
 *    Used by: kprobe_detector, become_root_detector, hooking_audit_detector, etc.
 *
 * 2. PHOTON_RING_KPROBE_GET_ARG(regs, n) — for kprobe-based detectors
 *    Extracts the nth function argument from pt_regs (CPU register snapshot).
 *    Used by: bpf_hook_detector (which must use kprobes because ftrace cannot
 *    hook its own infrastructure — ftrace_set_filter_ip).
 *
 * Both macros map argument indices to architecture-specific registers:
 *   x86_64: arg0=RDI, arg1=RSI, arg2=RDX, arg3=RCX, arg4=R8, arg5=R9
 *   ARM64:  arg0=X0,  arg1=X1,  arg2=X2,  ...,       arg7=X7
 *
 * Modern kernels (6.x+) with CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS provide
 * ftrace_regs_get_argument() which works across all architectures.
 * We use that when available, falling back to pt_regs for older kernels.
 */

/*
 * ============================================================
 * Kprobe argument extraction (from struct pt_regs)
 * ============================================================
 * Kprobe handlers receive a raw pt_regs snapshot of CPU registers at the
 * probed function's entry point. We need architecture-specific mappings
 * to extract function arguments from the correct registers.
 *
 * On modern kernels (5.x+), regs_get_kernel_argument() provides this
 * portably. For older kernels, we fall back to direct register access.
 */
#if defined(regs_get_kernel_argument) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

#define PHOTON_RING_KPROBE_GET_ARG(regs, n) \
    regs_get_kernel_argument(regs, n)

#else /* Fallback for older kernels without regs_get_kernel_argument */

#if defined(__x86_64__) || defined(__i386__)

#define PHOTON_RING_KPROBE_GET_ARG(regs, n) ({ \
    unsigned long _val; \
    switch(n) { \
        case 0: _val = (regs)->di; break; \
        case 1: _val = (regs)->si; break; \
        case 2: _val = (regs)->dx; break; \
        case 3: _val = (regs)->cx; break; \
        case 4: _val = (regs)->r8; break; \
        case 5: _val = (regs)->r9; break; \
        default: _val = 0; break; \
    } \
    _val; \
})

#elif defined(__aarch64__) || defined(__arm__)

#define PHOTON_RING_KPROBE_GET_ARG(regs, n) ({ \
    unsigned long _val; \
    if ((n) < 8) { \
        _val = (regs)->regs[n]; \
    } else { \
        _val = 0; \
    } \
    _val; \
})

#else
#warning "Unknown architecture for kprobe argument extraction"
#define PHOTON_RING_KPROBE_GET_ARG(regs, n) (0UL)
#endif

#endif /* regs_get_kernel_argument */


// #ifdef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS
// #include <linux/ftrace_regs.h>

/* Use the portable ftrace_regs API (works on x86_64, ARM64, etc.) */
// #define PHOTON_RING_GET_ARG(fregs, n) ftrace_regs_get_argument(fregs, n)

/*
 * With FTRACE_WITH_ARGS, arguments are saved automatically.
 * No need for FTRACE_OPS_FL_SAVE_REGS.
 */
// #define PHOTON_RING_FTRACE_FLAGS (FTRACE_OPS_FL_RECURSION)

// #else /* !CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS */

/* Fallback for older kernels that use pt_regs */
#include <asm/ptrace.h>

#if defined(__x86_64__) || defined(__i386__)

#define PHOTON_RING_GET_ARG(fregs, n) ({ \
    unsigned long _val; \
    struct pt_regs *_regs = ftrace_get_regs(fregs); \
    if (_regs) { \
        switch(n) { \
            case 0: _val = _regs->di; break; \
            case 1: _val = _regs->si; break; \
            case 2: _val = _regs->dx; break; \
            case 3: _val = _regs->cx; break; \
            case 4: _val = _regs->r8; break; \
            case 5: _val = _regs->r9; break; \
            default: _val = 0; break; \
        } \
    } else { \
        _val = 0; \
    } \
    _val; \
})

#elif defined(__aarch64__) || defined(__arm__)

#define PHOTON_RING_GET_ARG(fregs, n) ({ \
    unsigned long _val; \
    struct pt_regs *_regs = ftrace_get_regs(fregs); \
    if (_regs && (n) < 8) { \
        _val = _regs->regs[n]; \
    } else { \
        _val = 0; \
    } \
    _val; \
})

#else
#warning "Unknown architecture and no FTRACE_WITH_ARGS support"
#define PHOTON_RING_GET_ARG(fregs, n) (0UL)
#endif

#define PHOTON_RING_FTRACE_FLAGS (FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION)

#endif /* CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS */

// #endif /* PHOTON_RING_ARCH_H */
