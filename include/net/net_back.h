#include <sys/socket.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <net/net_common.h>

typedef struct {
    struct sockaddr_in addr;
    int sockd;
    pthread_mutex_t* fs_lock;
    atomic_bool* stop_serving;
} server_info;

typedef struct {
    int connection_fd;
    int fs_fd;
    pthread_mutex_t* fs_lock;
    size_t current_inode_index;
    char** current_path;
    size_t current_depth;
} serve_session;

server_info init_server(int port);

void listen_connections(server_info info, int fs_fd);
cd_response get_cd_response(size_t dirs, char** path);

void* serve_client(void* args);

int serve_operation(serve_session* session);
void process_operation(struct request_command* command, int fs_fd, serve_session* session);
void server_stop(server_info info);
