#include "server.h"

#define READ_BYTE_SIZE 8192

#define QUEUE_DEPTH 256

#define EVENT_TYPE_ACCEPT 0
#define EVENT_TYPE_READ   1
#define EVENT_TYPE_WRITE  2

//The static root directory that we serve files from (needs to be fully qualified)
char* static_rootdir = nullptr;
size_t static_rootdir_len = 0;

//For simplicity we initially assume a prefix for all static files -- others are assumed to be dynamic
const char* static_prefix = "/static/";

//The full path we will use to access files -- built from static_rootdir + request path
char fullpath[PATH_MAX + 1];
char normalizedpath[PATH_MAX + 1];

#define HTTP_MAX_REQUEST_SIZE 8192
char http_request[HTTP_MAX_REQUEST_SIZE];

#define SERVER_STRING "Server: Bosque RSHook\r\n"

const char* unsupported_verb = \
                                "HTTP/1.0 400 Bad Request\r\n"
                                "Content-type: text/html\r\n"
                                "\r\n"
                                "<html>"
                                "<head>"
                                "<title>Unsupported Operation Type</title>"
                                "</head>"
                                "<body>"
                                "<h1>Bad Request</h1>"
                                "<p>REST Style hooks for Bosque services should be GET or POST</p>"
                                "</body>"
                                "</html>";


const char* http_bad_request = \
                                "HTTP/1.0 400 Bad Request\r\n"
                                "Content-type: text/html\r\n"
                                "\r\n"
                                "<html>"
                                "<head>"
                                "<title>Bad Request</title>"
                                "</head>"
                                "<body>"
                                "<h1>Bad Request (400)</h1>"
                                "<p>Malformed or invalid request</p>"
                                "</body>"
                                "</html>";

const char* http_404_static_content = \
                                "HTTP/1.0 404 Not Found\r\n"
                                "Content-type: text/html\r\n"
                                "\r\n"
                                "<html>"
                                "<head>"
                                "<title>Resource Not Found</title>"
                                "</head>"
                                "<body>"
                                "<h1>Not Found (404)</h1>"
                                "<p>Request for an unknown static resource</p>"
                                "</body>"
                                "</html>";

struct request
{
    int event_type;
    int iovec_count;
    int client_socket;
    struct iovec iov[];
};

struct io_uring ring;

void string_to_lower(char* str) {
    if(str == nullptr) {
        return;
    }

    for (int i = 0; str[i] != '\0'; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}

int get_line(const char *src, char *dest, size_t dest_sz) {
    for (size_t i = 0; i < dest_sz; i++)
    {
        dest[i] = src[i];
        if (src[i] == '\r' && src[i + 1] == '\n')
        {
            dest[i] = '\0';
            return 0;
        }
    }
    return 1;
}

void sigint_handler(int signo)
{
    io_uring_queue_exit(&ring);
    free(static_rootdir);

    printf("shutdown\n");
    exit(0);
}

void initialize(const char* static_files_root)
{
    static_rootdir = realpath(static_files_root, nullptr);
    if(static_rootdir == nullptr) {
        static_rootdir_len = 0;
    }
    else {
        static_rootdir_len = strlen(static_rootdir);
    }
    
    signal(SIGINT, sigint_handler);
    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
}

std::optional<std::string> setup_listening_socket(int port, int& sock)
{
    struct sockaddr_in srv_addr;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return std::optional<std::string>("Failed to create socket");
    }

    int enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        return std::optional<std::string>("Failed to set socket options");
    }

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (const struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) {
        return std::optional<std::string>("Failed to bind socket");
    }
    
    if (listen(sock, 128) < 0) {
        return std::optional<std::string>("Failed to listen on socket");
    }

    return std::nullopt;
}

int add_accept_request(int server_socket, struct sockaddr_in *client_addr, socklen_t *client_addr_len)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_accept(sqe, server_socket, (struct sockaddr *)client_addr, client_addr_len, 0);

    struct request* req = (struct request*)malloc(sizeof(struct request));
    req->event_type = EVENT_TYPE_ACCEPT;
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);

    return 0;
}

int add_read_request(int client_socket)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    struct request* req = (struct request*)malloc(sizeof(struct request) + sizeof(struct iovec));
    req->iov[0].iov_base = malloc(READ_BYTE_SIZE);
    req->iov[0].iov_len = READ_BYTE_SIZE;
    req->event_type = EVENT_TYPE_READ;
    req->client_socket = client_socket;
    memset(req->iov[0].iov_base, 0, READ_BYTE_SIZE);

    io_uring_prep_readv(sqe, client_socket, &req->iov[0], 1, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

int add_write_request(struct request *req)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    req->event_type = EVENT_TYPE_WRITE;

    io_uring_prep_writev(sqe, req->client_socket, req->iov, req->iovec_count, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(&ring);
    return 0;
}

//For responding with static error messages
void _send_static_string_content(const char *str, int client_socket) 
{
    struct request* req = (struct request*)malloc(sizeof(struct request) + sizeof(struct iovec));
    size_t slen = strlen(str);
    req->iovec_count = 1;
    req->client_socket = client_socket;
    req->iov[0].iov_base = malloc(slen);
    req->iov[0].iov_len = slen;
    memcpy(req->iov[0].iov_base, str, slen);
    add_write_request(req);
}

void handle_unimplemented_method(int client_socket) 
{
    _send_static_string_content(unsupported_verb, client_socket);
}

void handle_http_404(int client_socket) 
{
    _send_static_string_content(http_404_static_content, client_socket);
}

void handle_http_400(int client_socket) 
{
    _send_static_string_content(http_bad_request, client_socket);
}

std::optional<char*> copy_file_contents(const char* file_path, off_t file_size)
{
    //TODO: cache files here to avoid repeated reads

    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        return std::nullopt;
    }

    char* buf = (char*)malloc(file_size);
    int ret = read(fd, buf, file_size);
    if (ret < file_size)
    {
        free(buf);
        return std::nullopt;
    }
    close(fd);

    return buf;
}

const char* get_filename_ext(const char* filename)
{
    const char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) {
        return "";
    }
    else {
        return dot + 1;
    }
}

void send_headers(const char* path, off_t len, struct iovec *iov)
{
    size_t slen;
    char send_buffer[256];

    const char *str = "HTTP/1.0 200 OK\r\n";
    slen = strlen(str);
    iov[0].iov_base = malloc(slen);
    iov[0].iov_len = slen;
    memcpy(iov[0].iov_base, str, slen);

    slen = strlen(SERVER_STRING);
    iov[1].iov_base = malloc(slen);
    iov[1].iov_len = slen;
    memcpy(iov[1].iov_base, SERVER_STRING, slen);

    const char* file_ext = get_filename_ext(path);
    if (strcmp("jpg", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: image/jpeg\r\n");
    }
    else if (strcmp("jpeg", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: image/jpeg\r\n");
    }
    else if (strcmp("png", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: image/png\r\n");
    }
    else if (strcmp("gif", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: image/gif\r\n");
    }
    else if (strcmp("html", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: text/html\r\n");
    }
    else if (strcmp("js", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: application/javascript\r\n");
    }
    else if (strcmp("css", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: text/css\r\n");
    }
    else if (strcmp("txt", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: text/plain\r\n");
    }
    else if (strcmp("json", file_ext) == 0) {
        strcpy(send_buffer, "Content-Type: application/json\r\n");
    }
    else {
        strcpy(send_buffer, "Content-Type: application/octet-stream\r\n");
    }
    
    slen = strlen(send_buffer);
    iov[2].iov_base = malloc(slen);
    iov[2].iov_len = slen;
    memcpy(iov[2].iov_base, send_buffer, slen);

    /* Send the content-length header, which is the file size in this case. */
    sprintf(send_buffer, "content-length: %ld\r\n", len);
    slen = strlen(send_buffer);
    iov[3].iov_base = malloc(slen);
    iov[3].iov_len = slen;
    memcpy(iov[3].iov_base, send_buffer, slen);

    /*
     * When the browser sees a '\r\n' sequence in a line on its own,
     * it understands there are no more headers. Content may follow.
     * */
    strcpy(send_buffer, "\r\n");
    slen = strlen(send_buffer);
    iov[4].iov_base = malloc(slen);
    iov[4].iov_len = slen;
    memcpy(iov[4].iov_base, send_buffer, slen);
}

void handle_get_file_method(const char* path, int client_socket)
{
    if (static_rootdir_len + strlen(path) > PATH_MAX)
    {
        handle_http_404(client_socket);
        return;
    }

    strcpy(fullpath, static_rootdir);
    strcpy(fullpath + static_rootdir_len, path + (strlen(static_prefix) - 1)); //Skip the static prefix but leave the /

    char* npath = realpath(fullpath, normalizedpath);
    if(npath == nullptr || strncmp(npath, static_rootdir, static_rootdir_len) != 0) //Make sure we are not escaping the root dir
    {
        handle_http_404(client_socket);
        return;
    }

    struct stat path_stat;
    if (stat(npath, &path_stat) == -1)
    {
        handle_http_404(client_socket);
    }
    else
    {
        /* Check if this is a normal/regular file and not a directory or something else */
        if (!S_ISREG(path_stat.st_mode))
        {
            handle_http_404(client_socket);
            return;
        }

        std::optional<char*> data = copy_file_contents(npath, path_stat.st_size);
        if(!data.has_value())
        {
            handle_http_404(client_socket);
            return;
        }

        struct request* req = (struct request*)malloc(sizeof(struct request) + (sizeof(struct iovec) * 6));
        req->iovec_count = 6;
        req->client_socket = client_socket;
        send_headers(npath, path_stat.st_size, req->iov);
        
        req->iov[5].iov_base = data.value();
        req->iov[5].iov_len = path_stat.st_size;

        add_write_request(req);
    }
}

void handle_http_method(char* method_buffer, int client_socket) {
    char* saveptr = nullptr;

    const char* method = strtok_r(method_buffer, " ", &saveptr);
    const char* path = strtok_r(NULL, " ", &saveptr);

    string_to_lower((char*)method);
    if (strcmp(method, "get") == 0)
    {
        if(strncmp(path, static_prefix, strlen(static_prefix)) == 0)
        {
            handle_get_file_method(path, client_socket);
        }
        else
        {
            //TODO: we plan to add dynamic handling here later
            handle_unimplemented_method(client_socket);
        }
    }
    else
    {
        handle_unimplemented_method(client_socket);
    }
}

void handle_client_request(struct request* req)
{
    if (get_line((const char*) req->iov[0].iov_base, http_request, sizeof(http_request))) {
        handle_http_400(req->client_socket);
    }
    else {
        handle_http_method(http_request, req->client_socket);
    }
}

int server_loop(int server_socket) {
    struct io_uring_cqe* cqe;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    add_accept_request(server_socket, &client_addr, &client_addr_len);

    printf("Server listening...\n");

    while (1)
    {
        int ret = io_uring_wait_cqe(&ring, &cqe);
        struct request* req = (struct request *)cqe->user_data;
        if (ret < 0) {
            //fatal error -- return to main for cleanup
            return ret; //the error code -- later we might be able to recover from some errors
        }

        if (cqe->res < 0) {
            //fatal error -- return to main for cleanup
            return cqe->res; //the error code -- later we might be able to recover from some errors
        }

        switch (req->event_type) {
        case EVENT_TYPE_ACCEPT:
            add_accept_request(server_socket, &client_addr, &client_addr_len);
            add_read_request(cqe->res);
            free(req);
            break;
        case EVENT_TYPE_READ:
            handle_client_request(req);
            free(req->iov[0].iov_base);
            free(req);
            break;
        case EVENT_TYPE_WRITE:
            for (int i = 0; i < req->iovec_count; i++) {
                free(req->iov[i].iov_base);
            }
            close(req->client_socket);
            free(req);
            break;
        }

        io_uring_cqe_seen(&ring, cqe);
    }
}
