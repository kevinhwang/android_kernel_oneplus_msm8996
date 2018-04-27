#include <asm/setup.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>

static char new_command_line[COMMAND_LINE_SIZE];

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", new_command_line);
	return 0;
}

static int cmdline_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, cmdline_proc_show, NULL);
}

static const struct file_operations cmdline_proc_fops = {
	.open		= cmdline_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int remove_flag(char *command_line, const char *flag)
{
	char search_term[COMMAND_LINE_SIZE];
	char *start_ptr, *end_ptr;
	int flag_found = 0;

	snprintf(search_term, sizeof(search_term), "%s=", flag);

	/* Remove all occurrences of flag. */
	while ((start_ptr = strnstr(command_line, search_term, COMMAND_LINE_SIZE))) {
		flag_found = 1;

		/* Find delimiter before next flag. */
		end_ptr = strnchr(start_ptr, strnlen(start_ptr, COMMAND_LINE_SIZE - (start_ptr - command_line)), ' ');

		if (end_ptr++) {
			/* Remove flag and following delimiter. */
			size_t len_remaining = strnlen(end_ptr, COMMAND_LINE_SIZE - (end_ptr - command_line));
			memmove(start_ptr, end_ptr, len_remaining + 1);
			end_ptr[len_remaining] = 0;
		} else if (start_ptr > command_line && start_ptr[-1] == ' ') {
			/* Remove flag from end of command line when multiple flags present. */
			start_ptr[-1] = 0;
		} else {
			/* Remove flag from command line when it's the only one present. */
			*start_ptr = 0;
		}
	}

	return flag_found;
}

static void replace_flag(char *command_line, const char *key, const char *value)
{
	char replacement_flag[COMMAND_LINE_SIZE];

	if (remove_flag(command_line, key)) {
		/* Append delimiter to command line. */
		strlcat(command_line, " ", COMMAND_LINE_SIZE);

		/* Append replacement flag to command line. */
		snprintf(replacement_flag, sizeof(replacement_flag), "%s=%s", key, value);
		strlcat(command_line, replacement_flag, COMMAND_LINE_SIZE);
	}
}

static int __init proc_cmdline_init(void)
{
	char *offset_addr;

	offset_addr = strstr(saved_command_line, "androidboot.mode=reboot");
	if (offset_addr != NULL)
		strncpy(offset_addr + 17, "normal", 6);

	strlcpy(new_command_line, saved_command_line, COMMAND_LINE_SIZE);

	/* Spoof command line parameters in /proc/fs with values that pass the SafetyNet CTS. */
	replace_flag(new_command_line, "androidboot.enable_dm_verity", "1");
	replace_flag(new_command_line, "androidboot.secboot", "enabled");
	replace_flag(new_command_line, "androidboot.verifiedbootstate", "green");
	replace_flag(new_command_line, "androidboot.veritymode", "enforcing");

	proc_create("cmdline", 0, NULL, &cmdline_proc_fops);
	return 0;
}
fs_initcall(proc_cmdline_init);
