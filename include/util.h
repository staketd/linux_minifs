#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <errno.h>

size_t min(size_t a, size_t b);
int exit_fatal(char* error);

int open_fs(const char* filename);

void unmap(void* addr, size_t length);

char* split_address(const char* host_port, int* port);

void print_errno();
