#ifndef PHOTON_RING_WATCHLIST_RESOLVER_H
#define PHOTON_RING_WATCHLIST_RESOLVER_H

/*
 * watchlist_resolver.h — Photon Ring
 *
 * Interface for the address → name dictionary covering every symbol in
 * photon_watchlist[].  Storage and implementations live in watchlist_resolver.c;
 * this header is safe to include from multiple translation units.
 *
 * Usage
 * -----
 *   1. Call watchlist_resolver_populate(kallsyms_fn) once during
 *      kprobe_detector_init(), after g_kallsyms_addr has been set.
 *   2. Call watchlist_resolver_lookup_name(addr) from any detector to
 *      reverse-map a raw kernel address back to its watchlisted symbol name.
 *      Returns NULL if the address is not in the table.
 */

#include <linux/types.h>

/*
 * Maximum number of dictionary entries.  One slot per non-NULL element of
 * photon_watchlist[]; unused slots are zeroed and skipped by the lookup.
 */
#define WATCHLIST_RESOLVER_MAX_ENTRIES 128

/*
 * One entry in the address → name dictionary.
 * Defined here so callers can size arrays or embed the struct if needed,
 * but direct access to the table should go through the API below.
 */
struct watchlist_entry {
    unsigned long  addr;   /* resolved kernel virtual address          */
    const char    *name;   /* stable pointer into photon_watchlist[]   */
};

/*
 * Prototype for kallsyms_lookup_name called through a function pointer.
 * The symbol is unexported on kernels >= 5.7; the address must be supplied
 * by the caller (obtained via the kprobe bootstrap technique).
 */
typedef unsigned long (*kallsyms_lookup_name_fn)(const char *name);

/*
 * watchlist_resolver_populate - resolve every watchlisted symbol to an address.
 *
 * @kallsyms_fn: callable address of kallsyms_lookup_name.
 *
 * Symbols absent on this kernel build are silently skipped.
 * Must be called exactly once before any call to watchlist_resolver_lookup_name.
 */
void watchlist_resolver_populate(kallsyms_lookup_name_fn kallsyms_fn);

/*
 * watchlist_resolver_lookup_name - reverse-map a kernel address to a name.
 *
 * @addr: raw kernel address (e.g. kprobe.addr or ftrace_set_filter_ip's ip arg).
 *
 * Returns a stable pointer into photon_watchlist[], or NULL if not found.
 */
const char *watchlist_resolver_lookup_name(unsigned long addr);

#endif /* PHOTON_RING_WATCHLIST_RESOLVER_H */