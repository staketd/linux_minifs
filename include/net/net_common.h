#pragma once
#include <constants.h>
#include <stddef.h>
#include <fs/fs.h>

enum operation {
    FIN = 0,
    CAT,
    LSDIR,
    LS,
    RMF,
    RMD,
    MKDIR,
    CD,
    UPLOAD,
};

struct request_command {
    enum operation command;

    char path[BLOCK_SIZE];

    size_t upload_file_size;
};

typedef struct {
    long long path_len;
    char* path;
} cd_response;

void send_dirs(int sockd, struct dir_entry_list_node* now);

void send_current_path(int sockd, cd_response response);

void send_error(int sockd, const char* error);

void send_ok(int sockd);
