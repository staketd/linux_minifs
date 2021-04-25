#include <net/net_front.h>
#include <util.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

int get_connection(const char* address) {
    int port;
    char* host = split_address(address, &port);

    int sockd = socket(AF_INET, SOCK_STREAM, 0);

    struct hostent* hostent = gethostbyname(host);
    in_addr_t* ip = (in_addr_t*) (*hostent->h_addr_list);

    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(struct sockaddr_in));

    addr.sin_addr.s_addr = *ip;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    int result = connect(sockd, (const struct sockaddr*) &addr, sizeof(struct sockaddr_in));

    if (errno) {
        printf("%s", strerror(errno));
        exit(1);
    }

    free(host);

    return sockd;
}

void close_connection(int sockd) {
    close(sockd);
}

void send_request(struct request_command request, int sockd) {
    write(sockd, &request, sizeof(request));
}

void handle_response(int sockd, enum operation command, char** current_path) {
    if (command == LS || command == LSDIR) {
        struct dir_entry_list_node now;
        do {
            read(sockd, &now, sizeof(struct dir_entry_list_node));
            printf("%s\n", now.entry.name);
        } while (now.next != NULL);
        return;
    }
    long long content_length;
    read(sockd, &content_length, sizeof(long long));
    if (content_length == 0) {
        printf("OK\n");
        return;
    }
    if (command == CD && content_length > 0) {
        free(*current_path);
        *current_path = malloc(content_length);
    }
    if (content_length < 0) {
        printf("Error occurred: \n");
        content_length = -content_length;
    }
    char buffer[BLOCK_SIZE];
    size_t offset = 0;
    while (content_length > 0) {
        int bytes = read(sockd, buffer, min(BLOCK_SIZE, content_length));
        if (command == CD) {
            memcpy(*current_path + offset, buffer, bytes);
        } else {
            printf("%s", buffer);
        }
        content_length -= bytes;
        offset += bytes;
    }
    printf("\n");
}

