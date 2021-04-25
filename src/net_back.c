#include <net/net_back.h>
#include <util.h>
#include <malloc.h>
#include <pthread.h>
#include <memory.h>
#include <signal.h>
#include <unistd.h>
#include <net/net_common.h>
#include <fs/fs.h>
#include <pthread.h>


__thread int thread_current_sockd;
server_info global_info;

void sighandler(int sigid) {
    if (thread_current_sockd > 0)
        close(thread_current_sockd);

    pthread_mutex_unlock(global_info.fs_lock);
    pthread_exit(NULL);
}

void setup_sigterm_handler() {
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = sighandler;
    sigaction(SIGTERM, NULL, &act);
}

server_info init_server(int port) {
    server_info info;
    info.sockd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;

    info.addr.sin_family = AF_INET;
    info.addr.sin_port = htons(port);
    info.addr.sin_addr.s_addr = htonl(INADDR_ANY);

    info.stop_serving = malloc(sizeof(atomic_bool));
    atomic_init(info.stop_serving, 0);

    if (bind(info.sockd, (struct sockaddr*) &info.addr, sizeof(info.addr))) {
        exit_fatal("Unable to bind socket");
    }

    info.fs_lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(info.fs_lock, NULL);

    return info;
}

void listen_connections(server_info info, int fs_fd) {
    global_info = info;
    setup_sigterm_handler();

    listen(info.sockd, 5);
    print_errno();
    while (!atomic_load(info.stop_serving)) {
        int con_fd = accept(info.sockd, NULL, 0);
        if (con_fd == -1) {
            exit_fatal("Unable to accept connection");
        }
        serve_session* request = malloc(sizeof(serve_session));

        request->fs_lock = global_info.fs_lock;
        request->connection_fd = con_fd;
        request->fs_fd = fs_fd;
        pthread_t thread;
        pthread_create(&thread, NULL, serve_client, request);
        pthread_detach(thread);
    }
}

size_t start_inode(char first_symb, size_t current_inode_index) {
    return first_symb == '/' ? ROOT_INODE_INDEX : current_inode_index;
}

void process_operation(struct request_command* command, int fs_fd, serve_session* session) {
    char* path = command->path;
    switch (command->command) {
        case CAT: {
            char** splitted_path;
            size_t depth = split_path(path, &splitted_path);
            size_t inode_index = start_inode(path[0], session->current_inode_index);
            inode* inode = get_inode_of_file(fs_fd, splitted_path, depth, inode_index, NULL);
            if (inode == NULL) {
                send_error(session->connection_fd, "An error occurred during cat op");
                return;
            }
            long long file_size = inode->file_size;
            write(session->connection_fd, &file_size, sizeof(long long));
            free(inode);
            int res = concatenate_and_write_to_fd(fs_fd, splitted_path, depth,
                                                  inode_index,
                                                  session->connection_fd);
            if (res != 0) {
                exit_fatal("Something went wrong");
            }
            break;
        }
        case LSDIR: {
            struct dir_entry_list_node head;
            int res = list_directory(fs_fd, 0, NULL, session->current_inode_index, &head);
            if (res != 0) {
                send_error(session->connection_fd, "An error occurred during lsdir op");
                return;
            }
            send_dirs(session->connection_fd, &head);
            break;
        }
        case LS: {
            char** splitted_path;
            size_t depth = split_path(path, &splitted_path);
            struct dir_entry_list_node head;
            int res = list_directory(
                    fs_fd,
                    depth,
                    splitted_path,
                    start_inode(path[0], session->current_inode_index),
                    &head
            );
            if (res != 0) {
                send_error(session->connection_fd, "An error occurred during ls operation");
                return;
            }
            send_dirs(session->connection_fd, &head);
            free_path(splitted_path, depth);
            break;
        }
        case RMF: {
            char** splitted_path;
            size_t depth = split_path(path, &splitted_path);

            size_t inode_index = start_inode(path[0], session->current_inode_index);
            size_t file_inode_index;

            inode* file_inode = get_inode_of_file(
                    fs_fd,
                    splitted_path,
                    depth,
                    inode_index,
                    &file_inode_index
            );
            inode* folder_inode = get_inode_of_file(
                    fs_fd,
                    splitted_path,
                    depth - 1,
                    inode_index,
                    NULL
            );
            if (folder_inode == NULL || file_inode == NULL) {
                send_error(session->connection_fd, "Path does not exist");
                return;
            }
            if (check_directory(file_inode) == FOLDER_ATTR) {
                send_error(session->connection_fd, "Specified path is a directory");
                return;
            }
            remove_file(fs_fd, folder_inode, file_inode, file_inode_index);
            free(file_inode);
            free(folder_inode);
            send_ok(session->connection_fd);
            break;
        }
        case RMD: {
            char** splitted_path;
            size_t depth = split_path(path, &splitted_path);
            inode* folder_inode =
                    get_inode_of_file(fs_fd, splitted_path, depth, start_inode(path[0], session->current_inode_index),
                                      NULL);
            remove_dir(fs_fd, folder_inode);
            free(folder_inode);
            session->current_path = NULL;
            session->current_inode_index = ROOT_INODE_INDEX;
            session->current_depth = 0;
            break;
        }
        case MKDIR: {
            char** splitted_path;
            size_t depth = split_path(path, &splitted_path);
            if (make_dir(fs_fd, depth, splitted_path, start_inode(path[0], session->current_inode_index)) != 0) {
                send_error(session->connection_fd, "An error occurred during mkdir operation");
                return;
            }
            free_path(splitted_path, depth);
            send_ok(session->connection_fd);
            break;
        }
        case CD: {
            char** splitted_path;
            size_t depth = split_path(path, &splitted_path);
            void* inode = get_inode_of_file(fs_fd,
                                            splitted_path,
                                            depth,
                                            start_inode(path[0], session->current_inode_index),
                                            &session->current_inode_index
            );
            if (inode == NULL) {
                close(session->connection_fd);
                return;
            }
            free(inode);
            if (path[0] == '/') {
                free_path(session->current_path, session->current_depth);
                session->current_depth = depth;
                session->current_path = splitted_path;
            } else {
                char** new_path;
                session->current_depth = concat_paths(session->current_depth, session->current_path, depth,
                                                      splitted_path, &new_path);
                free(session->current_path);
                session->current_path = new_path;
                session->current_depth = canonize_path(&session->current_path, session->current_depth);
            }
            send_current_path(session->connection_fd, get_cd_response(session->current_depth, session->current_path));
            break;
        }
        case UPLOAD: {
            char** splitted_path;
            size_t depth = split_path(path, &splitted_path);

            int res = upload_file(fs_fd, session->connection_fd, splitted_path, depth,
                        start_inode(path[0], session->current_inode_index),
                        command->upload_file_size);
            if (res != 0) {
                send_error(session->connection_fd, "An error occurred during upload op");
                return;
            }
            send_ok(session->connection_fd);
            break;
        }
    }
}

int serve_operation(serve_session* session) {
    struct request_command operation;
    long bytes_read = read(session->connection_fd, &operation, sizeof(operation));
    if (bytes_read == -1) {
        exit_fatal("Unable to read from socket");
    }

    if (operation.command == FIN) {
        return 1;
    }

    if (bytes_read != sizeof(operation)) {
        return 0;
    }

    pthread_mutex_lock(session->fs_lock);
    process_operation(&operation, session->fs_fd, session);
    pthread_mutex_unlock(session->fs_lock);
    return 1;
}

void* serve_client(void* args) {
    serve_session* session = args;
    thread_current_sockd = session->connection_fd;
    session->current_inode_index = ROOT_INODE_INDEX;
    session->current_path = NULL;

    while (serve_operation(session));

    close(session->connection_fd);
    free(args);
    return NULL;
}

cd_response get_cd_response(size_t dirs, char** path) {
    cd_response result;
    if (dirs == 0) {
        result.path_len = 1;
        result.path = malloc(1);
        result.path[0] = '/';
        return result;
    }
    result.path_len = 0;
    for (size_t i = 0; i < dirs; ++i) {
        result.path_len += strlen(path[i]) + 1;
    }
    result.path = malloc(result.path_len + 1);
    memset(result.path, 0, result.path_len + 1);
    size_t offset = 0;
    for (size_t i = 0; i < dirs; ++i) {
        result.path[offset] = '/';
        size_t len = strlen(path[i]);
        memcpy(result.path + offset + 1, path[i], len);
        offset += len + 1;
    }
    return result;
}

void server_stop(server_info info) {
    close(info.sockd);
    free(info.stop_serving);
    pthread_mutex_destroy(info.fs_lock);
    free(info.fs_lock);
}
