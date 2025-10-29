#include "rshook.h"

struct io_uring ring;

void sigint_handler(int signo)
{
    io_uring_queue_exit(&ring);
    exit(0);
}

int main(int argc, char **argv) 
{
    return 0;
}
