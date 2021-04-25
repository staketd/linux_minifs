#include <net/net_common.h>
#include <fs/fs.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void send_dirs(int sockd, struct dir_entry_list_node* now) {
    while (now != NULL) {
        write(sockd, now, sizeof(struct dir_entry_list_node));
        now = now->next;
    }
}

void send_current_path(int sockd, cd_response response) {
    write(sockd, &response.path_len, sizeof(long long));
    write(sockd, response.path, response.path_len);
    free(response.path);
}

void send_error(int sockd, const char* error) {
    long long len = strlen(error);
    len = -len;
    write(sockd, &len, sizeof(long long));
    write(sockd, error, -len);
}

void send_ok(int sockd) {
    long long ok_code = 0;
    write(sockd, &ok_code, sizeof(long long));
}