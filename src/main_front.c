#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include "constants.h"
#include <net/net_front.h>
#include <sys/stat.h>
#include <unistd.h>
#include <util.h>

int main(int argc, char* argv[]) {
    int sockd = get_connection(argv[1]);
    char* current_path = malloc(2);
    current_path[0] = '/';
    current_path[1] = '\0';
    while (1 == 1) {
        printf(" $>%s", current_path);
        char command[20];
        scanf("%s", command);
        struct request_command operation;
        int upload_fd = -2;
        if (strcmp(command, "ls") == 0) {
            operation.command = LS;
            scanf("%s", operation.path);
        } else if (strcmp(command, "lsdir") == 0) {
            operation.command = LSDIR;
        } else if (strcmp(command, "mkdir") == 0) {
            operation.command = MKDIR;
            scanf("%s", operation.path);
        } else if (strcmp(command, "cd") == 0) {
            operation.command = CD;
            scanf("%s", operation.path);
        } else if (strcmp(command, "upload") == 0) {
            operation.command = UPLOAD;
            char file_path[BLOCK_SIZE];
            scanf("%s %s", file_path, operation.path);
            upload_fd = open(file_path, O_RDONLY);
            if (upload_fd == -1) {
                printf("File does not exists\n");
                continue;
            }
            struct stat st;
            if (fstat(upload_fd, &st)) {
                printf("Can't stat file");
                continue;
            }
            operation.upload_file_size = st.st_size;
        } else if (strcmp(command, "cat") == 0) {
            operation.command = CAT;
            scanf("%s", operation.path);
        } else if (strcmp(command, "rmf") == 0) {
            operation.command = RMF;
            scanf("%s", operation.path);
        } else if (strcmp(command, "rmd") == 0) {
            operation.command = RMF;
            scanf("%s", operation.path);
        } else {
            printf("Closing connection");
            operation.command = FIN;
            send_request(operation, sockd);
            close_connection(sockd);
            return 0;
        }
        send_request(operation, sockd);
        if (upload_fd != -2) {
            size_t offset = 0;
            char buffer[BLOCK_SIZE];
            while (offset < operation.upload_file_size) {
                int rd = read(upload_fd, buffer, min(BLOCK_SIZE, operation.upload_file_size - offset));
                write(sockd, buffer, rd);
                offset += rd;
            }
        }
        handle_response(sockd, operation.command, &current_path);
    }
}
