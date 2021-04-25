#include <util.h>

size_t min(size_t a, size_t b) {
    return (a < b ? a : b);
}

int exit_fatal(char* error) {
    perror(error);
    exit(1);
}

int open_fs(const char* filename) {
    int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        exit_fatal("Unable to open filesystem file");
    }
    return fd;
}

void unmap(void* addr, size_t length) {
    if (addr == NULL) {
        return;
    }
    munmap(addr, length);
}

char* split_address(const char* host_port, int* port) {
    char* pos = strchr(host_port, ':');
    if (pos == NULL) {
        exit_fatal("Invalid address");
    }
    if (!sscanf(pos + 1, "%d", port) || *port > UINT16_MAX) {
        exit_fatal("Invalid port");
    }
    char* host = malloc(pos - host_port + 1);
    memset(host, 0, pos - host_port + 1);
    memcpy(host, host_port, pos - host_port);
    return host;
}

void print_errno() {
    if (errno) {
        printf("%s\n", strerror(errno));
    }
}