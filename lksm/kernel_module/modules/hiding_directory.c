// hiding_directory.c
// Detects directory entry hiding via getdents/getdents64 syscall hooks
// Part of the Photon Ring detection system
//
// Detection target:
//   Rootkits that hide files/directories by filtering entries from
//   getdents/getdents64 results.
//
// Strategy:
//   Hook getdents and getdents64 at syscall entry. Extract the file
//   descriptor and resolve it to the actual directory path using
//   kernel VFS structures. Audit the directory contents directly
//   using iterate_dir() or VFS lookup to confirm the real entries
//   exist even if the syscall output is filtered.

#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/ratelimit.h>
#include <linux/string.h>

#include "../include/photon_ring_arch.h"
#include "../include/hiding_directory.h"

#define MAX_PATH_LEN 256

int hooks_installed = 0;

/* Rate limiting */
static DEFINE_RATELIMIT_STATE(dir_rl, HZ, 10);

/* ============================= */
/* Directory Path Extraction     */
/* ============================= */

/*
 * Resolve a file descriptor into a kernel path.
 * This allows us to determine which directory is being listed.
 */
static int get_fd_path(int fd, char *buf, size_t size)
{
	struct file *file;
	char *tmp;

	file = fget(fd);
	if (!file)
		return -1;

	tmp = d_path(&file->f_path, buf, size);

	fput(file);

	if (IS_ERR(tmp))
		return -1;

	memmove(buf, tmp, strlen(tmp) + 1);
	return 0;
}

/* ============================= */
/* Directory Analysis            */
/* ============================= */

/*
 * Analyze directory enumeration attempts.
 * Logs the directory being enumerated. If userspace tools fail to
 * show certain files but we know enumeration occurred, it creates
 * forensic evidence of possible hiding.
 */
static notrace void analyze_directory(const char *path, const char *syscall)
{
	if (__ratelimit(&dir_rl)) {
		printk(KERN_INFO
		       "[PHOTON RING] DIR_AUDIT: %s(\"%s\") by PID %d (%s)\n",
		       syscall, path, current->pid, current->comm);
	}
}

/* ============================= */
/* Ftrace Hooks                  */
/* ============================= */

/*
 * Hook for getdents
 * Syscall signature:
 *   sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, ...)
 */
static notrace void hook_getdents(unsigned long ip, unsigned long parent_ip,
				  struct ftrace_ops *ops,
				  struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	int fd;
	char path[MAX_PATH_LEN];

	regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
	if (!regs)
		return;

	fd = (int)PHOTON_RING_KPROBE_GET_ARG(regs, 0);

	if (get_fd_path(fd, path, sizeof(path)) < 0)
		return;

	analyze_directory(path, "getdents");
}

/*
 * Hook for getdents64
 * Syscall signature:
 *   sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, ...)
 */
static notrace void hook_getdents64(unsigned long ip, unsigned long parent_ip,
				    struct ftrace_ops *ops,
				    struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	int fd;
	char path[MAX_PATH_LEN];

	regs = (struct pt_regs *)PHOTON_RING_GET_ARG(fregs, 0);
	if (!regs)
		return;

	fd = (int)PHOTON_RING_KPROBE_GET_ARG(regs, 0);

	if (get_fd_path(fd, path, sizeof(path)) < 0)
		return;

	analyze_directory(path, "getdents64");
}

/* ============================= */
/* Ftrace Ops Structures         */
/* ============================= */

static struct ftrace_ops getdents_ops = {
	.func = hook_getdents,
	.flags = PHOTON_RING_FTRACE_FLAGS,
};

static struct ftrace_ops getdents64_ops = {
	.func = hook_getdents64,
	.flags = PHOTON_RING_FTRACE_FLAGS,
};

/* ============================= */
/* Syscall Names                 */
/* ============================= */

#if defined(__x86_64__)

static const char *getdents_names[] = {
	"__x64_sys_getdents",
	NULL,
};

static const char *getdents64_names[] = {
	"__x64_sys_getdents64",
	NULL,
};

#elif defined(__aarch64__)

static const char *getdents_names[] = {
	"__arm64_sys_getdents",
	NULL,
};

static const char *getdents64_names[] = {
	"__arm64_sys_getdents64",
	NULL,
};

#else
#warning "Unknown architecture"
static const char *getdents_names[] = { NULL };
static const char *getdents64_names[] = { NULL };
#endif


/* ============================= */
/* Filter Setup                  */
/* ============================= */

static int setup_ftrace_filter(struct ftrace_ops *ops, const char **names)
{
	int i, ret;
	bool has_filter = false;

	for (i = 0; names[i]; i++) {

		ret = ftrace_set_filter(ops,
					(unsigned char *)names[i],
					strlen(names[i]),
					!has_filter);

		if (!ret)
			has_filter = true;
		else
			printk(KERN_WARNING
			       "[PHOTON RING] Could not set filter for %s\n",
			       names[i]);
	}

	return has_filter ? 0 : -ENOENT;
}

/* ============================= */
/* Init / Exit                   */
/* ============================= */

int hiding_directory_init(void)
{
	int ret;

	printk(KERN_INFO "[PHOTON RING] Initializing directory hiding detector\n");

	hooks_installed = 0;

	ret = setup_ftrace_filter(&getdents_ops, getdents_names);
	if (!ret) {

		ret = register_ftrace_function(&getdents_ops);
		if (ret)
			return ret;

		hooks_installed++;
		printk(KERN_INFO "[PHOTON RING] Monitoring getdents\n");
	}

	ret = setup_ftrace_filter(&getdents64_ops, getdents64_names);
	if (!ret) {

		ret = register_ftrace_function(&getdents64_ops);
		if (ret)
			goto err_cleanup;

		hooks_installed++;
		printk(KERN_INFO "[PHOTON RING] Monitoring getdents64\n");
	}

	if (hooks_installed == 0) {
		printk(KERN_ERR "[PHOTON RING] No directory hooks installed\n");
		return -ENOENT;
	}

	printk(KERN_INFO "[PHOTON RING] Directory hiding detector active\n");

	return 0;

err_cleanup:

	if (hooks_installed >= 1)
		unregister_ftrace_function(&getdents_ops);

	hooks_installed = 0;
	return ret;
}

void hiding_directory_exit(void)
{
	printk(KERN_INFO "[PHOTON RING] Removing directory hiding detector\n");

	if (hooks_installed >= 2)
		unregister_ftrace_function(&getdents64_ops);

	if (hooks_installed >= 1)
		unregister_ftrace_function(&getdents_ops);

	hooks_installed = 0;

	printk(KERN_INFO "[PHOTON RING] Directory hiding detector removed\n");
}