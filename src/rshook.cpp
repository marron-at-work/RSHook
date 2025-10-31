#include "server/server.h"

#define DEFAULT_SERVER_PORT 8000

int main(int argc, char **argv)
{
    initialize("./build/static/");

    int server_socket_fd;
    setup_listening_socket(DEFAULT_SERVER_PORT, server_socket_fd);

    server_loop(server_socket_fd);
}
