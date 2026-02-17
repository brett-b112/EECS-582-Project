#ifndef PHOTON_RING_ARCH_H
#define PHOTON_RING_ARCH_H

#include <linux/ftrace.h>

/*
 * Architecture-specific macros for Photon Ring
 * 
 * This file provides portability across different architectures (x86_64, ARM, etc.)
 */

#if defined(__x86_64__) || defined(__i386__)
/*
 * x86/x86_64 architecture
 */

#include <asm/ptrace.h>

/* Get function argument from ftrace_regs */
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
/*
 * ARM/ARM64 architecture
 */

#include <asm/ptrace.h>

/* Get function argument from ftrace_regs */
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
/*
 * Generic fallback for other architectures
 */

#warning "Unknown architecture, using generic ftrace argument access"

#define PHOTON_RING_GET_ARG(fregs, n) ({ \
    unsigned long _val = 0; \
    struct pt_regs *_regs = ftrace_get_regs(fregs); \
    if (_regs) { \
        /* This is architecture-specific and may not work */ \
        /* You'll need to implement this for your architecture */ \
        _val = 0; \
    } \
    _val; \
})

#endif

/* Ftrace flags configuration */
#define PHOTON_RING_FTRACE_FLAGS (FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION)

#endif /* PHOTON_RING_ARCH_H */