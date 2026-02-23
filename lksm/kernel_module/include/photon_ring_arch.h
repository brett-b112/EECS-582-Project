#ifndef PHOTON_RING_ARCH_H
#define PHOTON_RING_ARCH_H

#include <linux/ftrace.h>

/*
 * Architecture-portable macros for Photon Ring
 *
 * Modern kernels (6.x+) with CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS provide
 * ftrace_regs_get_argument() which works across all architectures.
 * We use that when available, falling back to pt_regs for older kernels.
 */

#ifdef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS
#include <linux/ftrace_regs.h>

/* Use the portable ftrace_regs API (works on x86_64, ARM64, etc.) */
#define PHOTON_RING_GET_ARG(fregs, n) \
    ftrace_regs_get_argument(fregs, n)

/*
 * With FTRACE_WITH_ARGS, arguments are saved automatically.
 * No need for FTRACE_OPS_FL_SAVE_REGS.
 */
#define PHOTON_RING_FTRACE_FLAGS (FTRACE_OPS_FL_RECURSION)

#else /* !CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS */

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

#endif /* PHOTON_RING_ARCH_H */
