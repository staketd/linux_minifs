#include <net/net_back.h>
#include <util.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syslog.h>

void init_fs_daemon(int port, const char* filename) {
    int fd = open_fs(filename);
    server_info info = init_server(port);

    char pwd[BLOCK_SIZE];
    getcwd(pwd, BLOCK_SIZE);
    strcat(pwd, "/file.pid");

    daemon(0, 0);

    int pid_file = open(pwd, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    dprintf(pid_file, "%d", getpid());
    close(pid_file);


    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));

    action.sa_flags = 0;
    action.sa_handler = SIG_IGN;
    sigaction(SIGABRT, NULL, &action);

    openlog("mini_fs_daemon", LOG_PID, LOG_DAEMON);

    listen_connections(info, fd);
    close(fd);
    server_stop(info);
    closelog();
}

int main(int argc, char* argv[]) {
    char* filename = argv[1];
    if (argc > 3 && !strcmp(argv[3], "--init")) {
        init(open_fs(filename));
    }
    int port = strtol(argv[2], NULL, 10);
    init_fs_daemon(port, filename);
    return 0;
}