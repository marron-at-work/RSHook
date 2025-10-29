#include "server.h"

void sigint_handler(int signo)
{
    printf("^C pressed. Shutting down.\n");
    io_uring_queue_exit(&ring);
    exit(0);
}

