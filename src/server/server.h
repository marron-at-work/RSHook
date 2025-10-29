#pragma once

#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdio.h>

#include <signal.h>
#include <liburing.h>

struct request
{
    int event_type;
    int iovec_count;
    int client_socket;
    struct iovec iov[];
};

struct io_uring ring;
