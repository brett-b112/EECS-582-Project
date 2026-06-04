/*
 * watchlist_resolver.c — Photon Ring
 *
 * Single compilation unit that owns the watchlist address dictionary.
 *
 * Previously the dictionary (watchlist_addr_table, watchlist_addr_table_len)
 * and the two functions were defined as static inline inside the header.
 * That caused each including translation unit (kprobe_detector.c,
 * ftrace_direct_detector.c, …) to get its own private zero-initialised copy
 * of the table.  kprobe_detector populated its copy during init, but every
 * other detector read from their own unpopulated copy — so lookups always
 * returned table_len=0 and no matches were ever found.
 *
 * Moving storage and implementations here ensures there is exactly one table
 * in the entire module, populated once and shared by all detectors.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include "watchlists.h"
#include "watchlist_resolver.h"

/* -------------------------------------------------------------------------
 * Storage — one copy for the entire module
 * -------------------------------------------------------------------------*/

struct watchlist_entry watchlist_addr_table[WATCHLIST_RESOLVER_MAX_ENTRIES];
int                    watchlist_addr_table_len = 0;

/* -------------------------------------------------------------------------
 * watchlist_resolver_populate
 * -------------------------------------------------------------------------*/

void watchlist_resolver_populate(kallsyms_lookup_name_fn kallsyms_fn)
{
    const char * const *entry;
    int idx = 0;

    if (!kallsyms_fn) {
        printk(KERN_ERR "[PHOTON RING] watchlist_resolver: populate called "
               "with NULL kallsyms_fn — table will be empty\n");
        return;
    }

    for (entry = photon_watchlist; *entry != NULL; entry++) {
        unsigned long addr;

        if (idx >= WATCHLIST_RESOLVER_MAX_ENTRIES) {
            printk(KERN_WARNING "[PHOTON RING] watchlist_resolver: table full "
                   "at %d entries — remaining symbols skipped\n", idx);
            break;
        }

        addr = kallsyms_fn(*entry);
        if (!addr) {
            /*
             * Symbol not present on this kernel build — expected for
             * arch-specific or version-specific entries; skip silently.
             */
            continue;
        }

        watchlist_addr_table[idx].addr = addr;
        watchlist_addr_table[idx].name = *entry;
        idx++;
    }

    watchlist_addr_table_len = idx;

    printk(KERN_INFO "[PHOTON RING] watchlist_resolver: resolved %d symbols "
           "into address table\n", idx);
}

/* -------------------------------------------------------------------------
 * watchlist_resolver_lookup_name
 * -------------------------------------------------------------------------*/

const char *watchlist_resolver_lookup_name(unsigned long addr)
{
    int i;

    if (!addr)
        return NULL;

    for (i = 0; i < watchlist_addr_table_len; i++) {
        if (watchlist_addr_table[i].addr == addr)
            return watchlist_addr_table[i].name;
    }

    return NULL;
}