#define FUSE_USE_VERSION 30

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <dirent.h>
#include <fuse.h>
#include <limits.h>

#define MAX_INPUT_SIZE 1024
#define CMD_HISTORY_FILE "cmd_h.txt"

#define RESET_COLOR "\033[0m"
#define ERROR_COLOR "\033[1;31m"
#define MESSAGE "\033[1;35m"

void reload_configuration(int sig);
void verify_boot_sector(const char *device);
void setup_virtual_fs();
void store_history(const char *command);
void read_history();
void exit_shell();
void process_command(char *args[]);
void display_env_var(char *arg);
void handle_echo(char *args[]);
void configure_signal_handling();
void execute_with_redirection(char *args[]);
void save_memory_dump(pid_t pid);

void reload_configuration(int sig)
{
    const char *msg =
        "\nConfiguration Reloaded\n";
    write(STDERR_FILENO, msg, strlen(msg));
}

void configure_signal_handling()
{
    struct sigaction sa = {0};
    sa.sa_handler = reload_configuration;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT, &sa, NULL);
}

void verify_boot_sector(const char *device)
{
    unsigned char buffer[512];
    char device_path[128];
    snprintf(device_path, sizeof(device_path), "/dev/%s", device);
    int fd = open(device_path, O_RDONLY);
    if (fd < 0)
    {
        perror("Error opening the device");
        return;
    }
    if (read(fd, buffer, sizeof(buffer)) != sizeof(buffer))
    {
        perror("Sector read error");
        close(fd);
        return;
    }
    close(fd);
    if (buffer[510] == 0x55 && buffer[511] == 0xAA)
        printf("Disk %s is bootable\n", device_path);
    else
        printf("Disk %s is NOT bootable\n", device_path);
}

static int vfs_getattr(const char *path, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0)
    {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    }
    else if (strcmp(path, "/tasks") == 0)
    {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = 1024;
    }
    else
        return -ENOENT;
    return 0;
}

static int vfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    if (strcmp(path, "/") != 0)
        return -ENOENT;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, "tasks", NULL, 0);
    return 0;
}

static int vfs_open(const char *path, struct fuse_file_info *fi)
{
    if (strcmp(path, "/tasks") != 0)
        return -ENOENT;
    return 0;
    // А
}

static int vfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    if (strcmp(path, "/tasks") != 0)
        return -ENOENT;
    FILE *cron = popen("crontab -l", "r");
    if (!cron)
        return -EIO;
    char tasks[1024];
    size_t len = fread(tasks, 1, sizeof(tasks), cron);
    pclose(cron);
    if (offset >= len)
        return 0;
    if (offset + size > len)
        size = len - offset;
    memcpy(buf, tasks + offset, size);
    return size;
}

static struct fuse_operations vfs_ops = {
    .getattr = vfs_getattr,
    .readdir = vfs_readdir,
    .open = vfs_open,
    .read = vfs_read,
};

void setup_virtual_fs()
{
    if (mkdir("/tmp/vfs", 0755) == -1 && errno != EEXIST)
    {
        perror("Got an error creating /tmp/vfs");
        return;
    }
    pid_t pid = fork();
    if (pid == 0)
    {
        if (setsid() < 0)
        {
            perror("setsid error");
            exit(EXIT_FAILURE);
        }
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        open("/dev/null", O_RDONLY);
        open("/dev/null", O_WRONLY);
        open("/dev/null", O_WRONLY);
        char *argv[] = {"vfs_cron", "/tmp/vfs", "-f", "-o", "nonempty", NULL};
        if (fuse_main(5, argv, &vfs_ops, NULL) == -1)
        {
            perror("FUSE error");
            exit(EXIT_FAILURE);
        }
        exit(0);
    }
    else if (pid < 0)
    {
        perror("fork error");
    }
    else
    {
        printf("VFS is mounted in /tmp/vfs. The cron task list is available.\n");
    }
}

void store_history(const char *command)
{
    int fd = open(CMD_HISTORY_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd != -1)
    {
        write(fd, command, strlen(command));
        write(fd, "\n", 1);
        close(fd);
    }
}

void read_history()
{
    int fd = open(CMD_HISTORY_FILE, O_RDONLY);
    if (fd != -1)
    {
        char buffer[4096];
        ssize_t bytes;
        while ((bytes = read(fd, buffer, sizeof(buffer))) > 0)
            write(STDOUT_FILENO, buffer, bytes);
        close(fd);
    }
    else
        printf("No history available.\n");
}

void exit_shell()
{
    printf("\nExiting\n");
    exit(0);
}

void process_command(char *args[])
{
    if (fork() == 0)
    {
        execvp(args[0], args);
        perror("Command execution error");
        exit(EXIT_FAILURE);
    }
    else
    {
        int status;
        wait(&status);
    }
}

void display_env_var(char *arg)
{
    if (arg[0] == '$')
    {
        char *value = getenv(arg + 1);
        printf("%s\n", value ? value : "Variable not found.");
    }
}

void handle_echo(char *args[])
{
    for (int i = 1; args[i]; i++)
    {
        printf("%s%s", args[i], args[i + 1] ? " " : "\n");
    }
}

void execute_with_redirection(char *args[])
{
    int i = 0, append = 0;
    while (args[i])
    {
        if (!strcmp(args[i], ">"))
        {
            append = 0;
            break;
        }
        if (!strcmp(args[i], ">>"))
        {
            append = 1;
            break;
        }
        i++;
    }
    if (!args[i])
    {
        process_command(args);
        return;
    }
    if (!args[i + 1])
    {
        fprintf(stderr, ERROR_COLOR "Error: file is missing.\n" RESET_COLOR);
        return;
    }
    args[i] = NULL;
    char *filename = args[i + 1];
    if (fork() == 0)
    {
        int fd = open(filename, O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0644);
        if (fd < 0)
        {
            perror(ERROR_COLOR "File opening error" RESET_COLOR);
            exit(EXIT_FAILURE);
        }
        dup2(fd, STDOUT_FILENO);
        close(fd);
        execvp(args[0], args);
        perror(ERROR_COLOR "Command execution error" RESET_COLOR);
        exit(EXIT_FAILURE);
    }
    else
    {
        int status;
        wait(&status);
    }
}

void save_memory_dump(pid_t pid)
{
    char filepath[256], output_file[256];
    snprintf(filepath, sizeof(filepath), "/proc/%d/maps", pid);
    snprintf(output_file, sizeof(output_file), "dump_%d.txt", pid);
    FILE *in = fopen(filepath, "r"), *out = fopen(output_file, "w");
    if (!in)
    {
        perror("Error opening maps");
        return;
    }
    if (!out)
    {
        perror("Dump creation error");
        fclose(in);
        return;
    }
    char line[4096];
    while (fgets(line, sizeof(line), in))
        fputs(line, out);
    fclose(in);
    fclose(out);
    printf("The memory dump of process %d is stored in %s\n", pid, output_file);
}

int main()
{
    char input[MAX_INPUT_SIZE], *args[128], cwd[PATH_MAX];
    configure_signal_handling();

    while (1)
    {
        if (getcwd(cwd, sizeof(cwd)))
            printf(MESSAGE "%s >> " RESET_COLOR, cwd);
        else
        {
            perror("Wrong directory");
            printf(MESSAGE "> " RESET_COLOR);
        }
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin))
        {
            if (feof(stdin))
                exit_shell();
            continue;
        }
        input[strcspn(input, "\n")] = 0;
        if (strlen(input))
            store_history(input);

        int i = 0;
        char *token = strtok(input, " ");
        while (token && i < 127)
            args[i++] = token, token = strtok(NULL, " ");
        args[i] = NULL;

        if (!args[0])
            continue;
        if (!strcmp(args[0], "exit") || !strcmp(args[0], "\\q"))
            exit_shell();
        else if (!strcmp(args[0], "history"))
            read_history();
        else if (!strcmp(args[0], "\\e") && args[1])
            display_env_var(args[1]);
        else if (!strcmp(args[0], "\\l") && args[1])
            verify_boot_sector(args[1]);
        else if (!strcmp(args[0], "\\cron"))
            setup_virtual_fs();
        else if (!strcmp(args[0], "\\mem") && args[1])
            save_memory_dump(atoi(args[1]));
        else if (!strcmp(args[0], "echo"))
            handle_echo(args);
        else
            execute_with_redirection(args);
    }
    return 0;
}
