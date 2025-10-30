#pragma once

#include "common.h"

#include <csignal>

#include <unistd.h>

#include <netinet/in.h>
#include <liburing.h>

void initialize(const char* static_files_root);

std::optional<std::string> setup_listening_socket(int port, int& sock);
int server_loop(int server_socket);