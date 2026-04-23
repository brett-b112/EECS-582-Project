// hiding_stat.c
// Detects stat-family syscall hiding and nlink manipulation attacks
// Part of the Photon Ring detection system
//
// Detection targets:
//   1. Path hiding - rootkit returns ENOENT for hidden files/PIDs
//   2. nlink manipulation - rootkit decreases directory nlink to hide subdirs
//   3. PID hiding via getpriority - rootkit returns ESRCH for hidden PIDs
//
// Strategy: Hook stat-family syscalls at entry and cross-verify paths
// against VFS (kern_path) and task list (find_task_by_vpid). The rootkit
// hooks at the syscall level but cannot intercept kernel-internal VFS
// lookups, so discrepancies reveal hidden entries.

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/ratelimit.h>
#include <linux/string.h>
#include <linux/resource.h>
#include "../include/photon_ring_arch.h"
#include "../include/hiding_stat.h"
#include "../include/event_manager.h"

#define MAX_PATH_LEN 256

int hooks_installed = 0;

/* Rate limiting: avoid flooding kernel log */
static DEFINE_RATELIMIT_STATE(stat_rl, HZ, 10);
static DEFINE_RATELIMIT_STATE(nlink_rl, HZ, 5);
static DEFINE_RATELIMIT_STATE(getprio_rl, HZ, 5);

/* ============================= */
/* Cross-Verification Helpers    */
/* ============================= */

/*
 * Extract numeric PID from a /proc/[pid]... path.
 * Returns the PID on success, -1 if not a /proc PID path.
 */
static int extract_proc_pid(const char *path)
{
	const char *p;
	char buf[16] = {0};
	int j = 0, pid;

	if (strncmp(path, "/proc/", 6) != 0)
		return -1;

	p = path + 6;
	while (j < (int)sizeof(buf) - 1 && p[j] >= '0' && p[j] <= '9') {
		buf[j] = p[j];
		j++;
	}
	if (j == 0)
		return -1;

	buf[j] = '\0';
	if (kstrtoint(buf, 10, &pid) < 0)
		return -1;
	return pid;
}

/*
 * Check if a PID has a real task_struct in the kernel task list.
 * This bypasses any syscall-level hiding since it queries the
 * scheduler data structures directly.
 */
static bool photon_pid_has_task(pid_t nr)
{
	struct pid *pid_struct;
	struct task_struct *task;
	bool exists;

	rcu_read_lock();
	pid_struct = find_vpid(nr);
	task = pid_struct ? pid_task(pid_struct, PIDTYPE_PID) : NULL;
	exists = (task != NULL);
	rcu_read_unlock();

	return exists;
}

/*
 * Verify a path exists at VFS level via kern_path.
 * Returns true if the path resolves successfully.
 * This bypasses syscall-level hooks (the rootkit only intercepts
 * stat/lstat/statx syscalls, not internal VFS lookups).
 */
static bool path_exists_in_vfs(const char *path)
{
	struct path p;
	int ret = kern_path(path, LOOKUP_FOLLOW, &p);
	if (ret == 0) {
		path_put(&p);
		return true;
	}
	return false;
}

/*
 * Get the real inode nlink count for a path, bypassing syscall hooks.
 * Returns the nlink count, or 0 on error.
 * Used to detect nlink manipulation: the rootkit modifies the stat
 * result in userspace but cannot change the actual inode.
 */
static unsigned int get_real_nlink(const char *path, bool *is_dir)
{
	struct path p;
	unsigned int nlink = 0;

	*is_dir = false;
	if (kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
		struct inode *inode = d_inode(p.dentry);
		if (inode) {
			nlink = inode->i_nlink;
			*is_dir = S_ISDIR(inode->i_mode);
		}
		path_put(&p);
	}
	return nlink;
}

/* ============================= */
/* Stat Path Analysis            */
/* ============================= */

/*
 * Analyze a path being stat'd for hiding anomalies.
 * Called at syscall entry time with the path argument.
 *
 * Detection logic:
 * - For /proc/[pid] paths: verify PID exists in task list. If it does,
 *   log an audit entry. If the rootkit later returns ENOENT, this entry
 *   proves the PID was valid (cross-reference with userspace observations).
 * - For directories: report real inode nlink count. If the rootkit reduces
 *   nlink in the stat result, comparing with this audit entry reveals the
 *   manipulation.
 */
static notrace void analyze_stat_path(const char *path, const char *syscall_name)
{
	int proc_pid;
	unsigned int real_nlink;
	bool is_dir;

	/* Check /proc PID paths for hidden process detection */
	proc_pid = extract_proc_pid(path);
	if (proc_pid > 0) {
		bool task_exists = photon_pid_has_task(proc_pid);
		bool vfs_exists = path_exists_in_vfs(path);

		if (task_exists && !vfs_exists) {
			/*
			 * CRITICAL: Task exists in scheduler but /proc entry
			 * is missing at VFS level. This indicates VFS-level
			 * proc hiding (different from syscall-level hiding).
			 */
			struct stat_event_data event_data;

			printk(KERN_ALERT
				"[PHOTON RING] CRITICAL: %s(\"%s\") - PID %d exists in tasklist but /proc entry missing at VFS level!\n",
				syscall_name, path, proc_pid);

			memset(&event_data, 0, sizeof(event_data));
			strncpy(event_data.syscall_name, syscall_name, sizeof(event_data.syscall_name) - 1);
			strncpy(event_data.path, path, sizeof(event_data.path) - 1);
			strncpy(event_data.caller_comm, current->comm, sizeof(event_data.caller_comm) - 1);
			event_data.caller_pid = current->pid;
			event_data.target_pid = (u32)proc_pid;
			event_data.real_nlink = 0;
			event_data.flags = STAT_FLAG_TASK_EXISTS | STAT_FLAG_VFS_MISSING;

			photon_log_event(PHOTON_EVENT_STAT_PATH_HIDDEN,
					 PHOTON_DETECTOR_STAT,
					 &event_data,
					 sizeof(event_data));
		} else if (task_exists && vfs_exists) {
			/*
			 * PID and /proc entry both exist. If the rootkit's
			 * syscall hook returns ENOENT for this path, this
			 * log entry proves the path was valid.
			 */
			if (__ratelimit(&stat_rl)) {
				struct stat_event_data event_data;

				printk(KERN_INFO
					"[PHOTON RING] STAT_AUDIT: %s(\"%s\") by PID %d (%s) - target PID %d verified in tasklist and VFS\n",
					syscall_name, path, current->pid,
					current->comm, proc_pid);

				memset(&event_data, 0, sizeof(event_data));
				strncpy(event_data.syscall_name, syscall_name, sizeof(event_data.syscall_name) - 1);
				strncpy(event_data.path, path, sizeof(event_data.path) - 1);
				strncpy(event_data.caller_comm, current->comm, sizeof(event_data.caller_comm) - 1);
				event_data.caller_pid = current->pid;
				event_data.target_pid = (u32)proc_pid;
				event_data.real_nlink = 0;
				event_data.flags = STAT_FLAG_TASK_EXISTS;

				photon_log_event(PHOTON_EVENT_STAT_PATH_HIDDEN,
						 PHOTON_DETECTOR_STAT,
						 &event_data,
						 sizeof(event_data));
			}
		}
		return;
	}

	/*
	 * For non-/proc paths: check nlink integrity on directories.
	 * The rootkit's adjust_user_stat_nlink() reduces nlink to hide
	 * subdirectories. By logging the real inode nlink here, we create
	 * evidence of manipulation.
	 */
	real_nlink = get_real_nlink(path, &is_dir);
	if (is_dir && real_nlink > 0 && __ratelimit(&nlink_rl)) {
		struct stat_event_data event_data;

		printk(KERN_INFO
			"[PHOTON RING] NLINK_AUDIT: %s(\"%s\") real_nlink=%u by PID %d (%s)\n",
			syscall_name, path, real_nlink,
			current->pid, current->comm);

		memset(&event_data, 0, sizeof(event_data));
		strncpy(event_data.syscall_name, syscall_name, sizeof(event_data.syscall_name) - 1);
		strncpy(event_data.path, path, sizeof(event_data.path) - 1);
		strncpy(event_data.caller_comm, current->comm, sizeof(event_data.caller_comm) - 1);
		event_data.caller_pid = current->pid;
		event_data.target_pid = 0;
		event_data.real_nlink = real_nlink;
		event_data.flags = STAT_FLAG_IS_DIR;

		photon_log_event(PHOTON_EVENT_STAT_NLINK_AUDIT,
				 PHOTON_DETECTOR_STAT,
				 &event_data,
				 sizeof(event_data));
	}
}

/* ============================= */
/* Ftrace Hook Callbacks         */
/* ============================= */

/*
 * Hook for stat/lstat/newstat/newlstat:
 * Syscall signature: sys_stat(const char __user *filename, ...)
 * pathname is the first syscall argument -> regs->di on x86_64
 */
static notrace void hook_stat_di(unsigned long ip, unsigned long parent_ip,
				 struct ftrace_ops *ops,
				 struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	const char __user *pathname;
	char kbuf[MAX_PATH_LEN];

	regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
	if (!regs)
		return;

	pathname = (const char __user *)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
	if (!pathname)
		return;

	if (strncpy_from_user(kbuf, pathname, sizeof(kbuf)) <= 0)
		return;
	kbuf[MAX_PATH_LEN - 1] = '\0';

	analyze_stat_path(kbuf, "stat");
}

/*
 * Hook for newfstatat/statx:
 * Syscall signature: sys_newfstatat(int dfd, const char __user *filename, ...)
 * pathname is the second syscall argument -> regs->si on x86_64
 */
static notrace void hook_stat_si(unsigned long ip, unsigned long parent_ip,
				 struct ftrace_ops *ops,
				 struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	const char __user *pathname;
	char kbuf[MAX_PATH_LEN];

	regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
	if (!regs)
		return;

	pathname = (const char __user *)PHOTON_RING_KPROBE_GET_ARG(regs, 1);
	if (!pathname)
		return;

	if (strncpy_from_user(kbuf, pathname, sizeof(kbuf)) <= 0)
		return;
	kbuf[MAX_PATH_LEN - 1] = '\0';

	analyze_stat_path(kbuf, "fstatat");
}

/*
 * Hook for getpriority:
 * Syscall signature: sys_getpriority(int which, int who)
 * The rootkit returns -ESRCH for hidden PIDs when which == PRIO_PROCESS.
 * We verify the PID actually exists to create an audit trail.
 */
static notrace void hook_getpriority_cb(unsigned long ip, unsigned long parent_ip,
					struct ftrace_ops *ops,
					struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	int which, who;

	regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
	if (!regs)
		return;

	which = (int)PHOTON_RING_KPROBE_GET_ARG(regs, 0);
	who = (int)PHOTON_RING_KPROBE_GET_ARG(regs, 1);

	if (which != PRIO_PROCESS || who <= 0)
		return;

	if (photon_pid_has_task(who) && __ratelimit(&getprio_rl)) {
		struct stat_event_data event_data;

		printk(KERN_INFO
			"[PHOTON RING] GETPRIORITY_AUDIT: getpriority(PRIO_PROCESS, %d) by PID %d (%s) - target PID verified in tasklist\n",
			who, current->pid, current->comm);

		memset(&event_data, 0, sizeof(event_data));
		strncpy(event_data.syscall_name, "getpriority", sizeof(event_data.syscall_name) - 1);
		/* path is not applicable for getpriority — leave zeroed */
		strncpy(event_data.caller_comm, current->comm, sizeof(event_data.caller_comm) - 1);
		event_data.caller_pid = current->pid;
		event_data.target_pid = (u32)who;
		event_data.real_nlink = 0;
		event_data.flags = STAT_FLAG_TASK_EXISTS;

		photon_log_event(PHOTON_EVENT_STAT_PID_AUDIT,
				 PHOTON_DETECTOR_STAT,
				 &event_data,
				 sizeof(event_data));
	}
}

/* ============================= */
/* Ftrace Ops Structures         */
/* ============================= */

static struct ftrace_ops stat_di_ops = {
	.func = hook_stat_di,
	.flags = PHOTON_RING_FTRACE_FLAGS,
};

static struct ftrace_ops stat_si_ops = {
	.func = hook_stat_si,
	.flags = PHOTON_RING_FTRACE_FLAGS,
};

static struct ftrace_ops getpriority_ops = {
	.func = hook_getpriority_cb,
	.flags = PHOTON_RING_FTRACE_FLAGS,
};

/* ============================= */
/* Syscall names to monitor      */
/* ============================= */

/* pathname in first arg: stat, lstat, newstat, newlstat */
#if defined(__x86_64__)
static const char *stat_di_names[] = {
	"__x64_sys_newstat",
	"__x64_sys_newlstat",
	"__x64_sys_stat",
	"__x64_sys_lstat",
	NULL,
};
static const char *stat_si_names[] = {
	"__x64_sys_newfstatat",
	"__x64_sys_statx",
	NULL,
};
#elif defined(__aarch64__)
static const char *stat_di_names[] = {
	"__arm64_sys_newstat",
	"__arm64_sys_newlstat",
	"__arm64_sys_stat",
	"__arm64_sys_lstat",
	NULL,
};
/* pathname in second arg: newfstatat, statx */
static const char *stat_si_names[] = {
	"__arm64_sys_newfstatat",
	"__arm64_sys_statx",
	NULL,
};
#else
#warning "Unknown architecture for syscall names"
static const char *stat_di_names[] = { NULL };
static const char *stat_si_names[] = { NULL };
#endif

/*
 * Register ftrace filter for multiple syscall names on one ftrace_ops.
 * Some syscalls may not exist on all kernel configurations, so failures
 * for individual names are logged as warnings but not fatal.
 * Returns 0 if at least one name was successfully filtered.
 */
static int setup_ftrace_filter(struct ftrace_ops *ops, const char **names)
{
	int i, ret;
	bool has_filter = false;

	for (i = 0; names[i]; i++) {
		/* reset=1 on first, reset=0 to append subsequent */
		ret = ftrace_set_filter(ops, (unsigned char *)names[i],
					strlen(names[i]),
					!has_filter);
		if (ret) {
			printk(KERN_WARNING
				"[PHOTON RING] Could not set filter for %s: %d (may not exist on this kernel)\n",
				names[i], ret);
		} else {
			has_filter = true;
			printk(KERN_INFO
				"[PHOTON RING] Filter set for %s\n",
				names[i]);
		}
	}

	return has_filter ? 0 : -ENOENT;
}

/* ============================= */
/* Init / Exit                   */
/* ============================= */

int hiding_stat_init(void)
{
	int ret;

	printk(KERN_INFO "[PHOTON RING] Initializing stat hiding detector...\n");

	hooks_installed = 0;

	/* Group 1: stat/lstat/newstat/newlstat (pathname in di) */
	ret = setup_ftrace_filter(&stat_di_ops, stat_di_names);
	if (ret == 0) {
		ret = register_ftrace_function(&stat_di_ops);
		if (ret) {
			printk(KERN_ERR
				"[PHOTON RING] Failed to register stat/lstat hooks: %d\n",
				ret);
			return ret;
		}
		hooks_installed++;
		printk(KERN_INFO
			"[PHOTON RING] Monitoring stat/lstat/newstat/newlstat\n");
	} else {
		printk(KERN_WARNING
			"[PHOTON RING] No stat/lstat syscalls found to hook\n");
	}

	/* Group 2: newfstatat/statx (pathname in si) */
	ret = setup_ftrace_filter(&stat_si_ops, stat_si_names);
	if (ret == 0) {
		ret = register_ftrace_function(&stat_si_ops);
		if (ret) {
			printk(KERN_ERR
				"[PHOTON RING] Failed to register fstatat/statx hooks: %d\n",
				ret);
			goto err_cleanup;
		}
		hooks_installed++;
		printk(KERN_INFO
			"[PHOTON RING] Monitoring newfstatat/statx\n");
	} else {
		printk(KERN_WARNING
			"[PHOTON RING] No fstatat/statx syscalls found to hook\n");
	}

	/* Group 3: getpriority (PID hiding detection) */
#if defined(__x86_64__)
	ret = ftrace_set_filter(&getpriority_ops,
				(unsigned char *)"__x64_sys_getpriority",
				strlen("__x64_sys_getpriority"), 1);
#elif defined(__aarch64__)
	ret = ftrace_set_filter(&getpriority_ops,
				(unsigned char *)"__arm64_sys_getpriority",
				strlen("__arm64_sys_getpriority"), 1);
#else
	ret = -ENOENT;
#endif
	if (ret == 0) {
		ret = register_ftrace_function(&getpriority_ops);
		if (ret) {
			printk(KERN_ERR
				"[PHOTON RING] Failed to register getpriority hook: %d\n",
				ret);
			goto err_cleanup;
		}
		hooks_installed++;
		printk(KERN_INFO
			"[PHOTON RING] Monitoring getpriority for PID hiding\n");
	} else {
		printk(KERN_WARNING
			"[PHOTON RING] Could not filter getpriority: %d\n", ret);
	}

	if (hooks_installed == 0) {
		printk(KERN_ERR
			"[PHOTON RING] No hooks installed, stat detector inactive\n");
		return -ENOENT;
	}

	printk(KERN_INFO
		"[PHOTON RING] Stat hiding detector active (%d hook groups)\n",
		hooks_installed);
	printk(KERN_INFO
		"[PHOTON RING] Detection coverage: path hiding, nlink manipulation, PID hiding\n");

	return 0;

err_cleanup:
	if (hooks_installed >= 2)
		unregister_ftrace_function(&stat_si_ops);
	if (hooks_installed >= 1)
		unregister_ftrace_function(&stat_di_ops);
	hooks_installed = 0;
	return ret;
}

void hiding_stat_exit(void)
{
	printk(KERN_INFO "[PHOTON RING] Removing stat hiding detector...\n");

	if (hooks_installed >= 3)
		unregister_ftrace_function(&getpriority_ops);
	if (hooks_installed >= 2)
		unregister_ftrace_function(&stat_si_ops);
	if (hooks_installed >= 1)
		unregister_ftrace_function(&stat_di_ops);

	hooks_installed = 0;
	printk(KERN_INFO "[PHOTON RING] Stat hiding detector removed\n");
}
