#include "constants.h"
#include <inttypes.h>
#include <stddef.h>
#include "net_common.h"

int get_connection(const char* address);
void close_connection(int sockd);

void send_request(struct request_command request, int sockd);
void handle_response(int sockd, enum operation command, char** current_path);
