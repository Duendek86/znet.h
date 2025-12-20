
/* zhttpd_async.c - v1.0.0 High-Performance (Linux Only)
 *
 * Usage:
 * ./zhttpd-async [DIR]
 * Example: ./zhttpd-async .
 *
 * COMPILE:
 * gcc zhttpd_async.c -o zhttpd-async -std=c11 -O3 -D_GNU_SOURCE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>

#define ZERROR_IMPLEMENTATION
#define ZERROR_SHORT_NAMES
#include "zerror.h"

#define ZFILE_IMPLEMENTATION
#include "zfile.h"

#define ZSTR_IMPLEMENTATION
#include "zstr.h"

#define ZNET_IMPLEMENTATION
#include "znet.h"

// Tunables.
#define MAX_CONNS 20000
#define BUF_SIZE  8192
#define MAX_EVENTS 1024
#define MAX_MIME_TYPES 256

// Config.
typedef struct 
{ 
    char ext[16]; 
    char type[128]; 
} MimeEntry;

struct GlobalConfig 
{
    int port;
    int workers;
    char root[1024];
    MimeEntry mimes[MAX_MIME_TYPES];
    int mime_count;
} g_cfg = 
{ 
    .port = 8080, 
    .root = "." 
};

static char g_date_header[64];
static time_t g_last_date = 0;

typedef enum 
{
    STATE_READ,
    STATE_WRITE_HEADER,
    STATE_WRITE_FILE,
    STATE_CLOSE
} conn_state;

typedef struct 
{
    int fd;
    conn_state state;
    char req[BUF_SIZE];
    int req_len;
    char res_head[1024];
    int head_len;
    int head_sent;
    int file_fd;
    off_t file_off;
    size_t file_rem;
    bool keep_alive;
    time_t last_active;
} zconn_t;

static __thread zconn_t *t_conns = NULL; 
static __thread int t_epoll_fd = -1;

// Config Loaders.

static void load_config_files(void) 
{
    if (zfile_exists("zhttpd.conf")) 
    {
        ZFILE_FOR_EACH_LINE("zhttpd.conf", line) 
        {
            zstr_view v = zstr_view_trim(line);
            if (0 == v.len || '#' == v.data[0])
            {
                continue;
            }
            zstr_split_iter it = zstr_split_init(v, "=");
            zstr_view k, val;
            if (zstr_split_next(&it, &k) && 
                zstr_split_next(&it, &val)) 
            {
                k = zstr_view_trim(k); 
                val = zstr_view_trim(val);
                if (zstr_view_eq(k, "port")) 
                {
                    zstr_view_to_int(val, &g_cfg.port);
                }
                if (zstr_view_eq(k, "root")) 
                {
                    snprintf(g_cfg.root, 1023, "%.*s", (int)val.len, val.data);
                }
            }
        }
    }
    
    strcpy(g_cfg.mimes[0].ext, ".html"); 
    strcpy(g_cfg.mimes[0].type, "text/html");
    g_cfg.mime_count = 1;

    if (zfile_exists("mime.conf")) 
    {
        ZFILE_FOR_EACH_LINE("mime.conf", line) 
        {
            zstr_view v = zstr_view_trim(line);
            if (0 == v.len || '#' == v.data[0]) 
            {
                continue;
            }
            zstr_split_iter it = zstr_split_init(v, "=");
            zstr_view ext, type;
            if (zstr_split_next(&it, &ext) && 
                zstr_split_next(&it, &type)) 
            {
                ext = zstr_view_trim(ext); 
                type = zstr_view_trim(type);
                if (g_cfg.mime_count < MAX_MIME_TYPES) 
                {
                    snprintf(g_cfg.mimes[g_cfg.mime_count].ext, 15, "%.*s", (int)ext.len, ext.data);
                    snprintf(g_cfg.mimes[g_cfg.mime_count].type, 127, "%.*s", (int)type.len, type.data);
                    g_cfg.mime_count++;
                }
            }
        }
    }
}

static const char* get_mime(const char *path) 
{
    const char *ext = strrchr(path, '.');
    if (!ext) 
    {
        return "application/octet-stream";
    }
    for(int i = 0; i < g_cfg.mime_count; i++) 
    {
        if (0 == strcmp(ext, g_cfg.mimes[i].ext)) 
        {
            return g_cfg.mimes[i].type;
        }
    }
    return "application/octet-stream";
}

// Logic.

static inline int znet_raw(znet_socket s) 
{ 
    return (int)s.handle; 
}

static void update_date(void) 
{
    time_t now = time(NULL);
    if (now != g_last_date) 
    {
        struct tm tm; 
        gmtime_r(&now, &tm);
        strftime(g_date_header, sizeof(g_date_header), "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", &tm);
        g_last_date = now;
    }
}

static void conn_reset(zconn_t *c) 
{
    c->state = STATE_READ; c->req_len = 0;
    c->head_len = 0; c->head_sent = 0;
    if (-1 != c->file_fd) 
    { 
        close(c->file_fd); 
        c->file_fd = -1; 
    }
    c->keep_alive = false; 
    c->last_active = time(NULL);
}

static void conn_close(zconn_t *c) 
{
    if (-1 != c->fd) 
    { 
        epoll_ctl(t_epoll_fd, EPOLL_CTL_DEL, c->fd, NULL); 
        close(c->fd); 
        c->fd = -1; 
    }
    conn_reset(c);
}

static void prepare_error(zconn_t *c, int code, const char *msg) 
{
    update_date();
    c->head_len = sprintf(c->res_head, 
        "HTTP/1.1 %d %s\r\nServer: zhttpd-async\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", 
        code, msg, g_date_header);
    c->keep_alive = false;
    c->state = STATE_WRITE_HEADER;
}

static void prepare_file(zconn_t *c, const char *path) 
{
    int fd = open(path, O_RDONLY);
    if (-1 == fd) 
    { 
        prepare_error(c, 404, "Not Found"); 
        return; 
    }
    
    struct stat st; 
    if (fstat(fd, &st) < 0 || S_ISDIR(st.st_mode)) 
    { 
        close(fd); 
        prepare_error(c, 403, "Forbidden"); 
        return; 
    }
    
    update_date();
    c->file_fd = fd; 
    c->file_rem = st.st_size; 
    c->file_off = 0;
    c->head_len = sprintf(c->res_head, "HTTP/1.1 200 OK\r\nServer: zhttpd-async\r\n%sContent-Type: %s\r\nContent-Length: %ld\r\nConnection: %s\r\n\r\n", 
        g_date_header, get_mime(path), st.st_size, c->keep_alive ? "keep-alive" : "close");
    c->state = STATE_WRITE_HEADER;
}

static void handle_io(zconn_t *c, uint32_t events) 
{
    c->last_active = time(NULL);
    if (events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) 
    { 
        conn_close(c); 
        return; 
    }

    if (events & EPOLLIN) 
    {
        int n = recv(c->fd, c->req + c->req_len, BUF_SIZE - c->req_len - 1, 0);
        if (n <= 0) 
        { 
            conn_close(c); 
            return; 
        }
        c->req_len += n; c->req[c->req_len] = 0;
        
        if (strstr(c->req, "\r\n\r\n")) 
        {
            char *method_end = strchr(c->req, ' ');
            if (!method_end) 
            { 
                conn_close(c); 
                return; 
            }
            
            char *path_start = method_end + 1;
            char *path_end = strchr(path_start, ' ');
            if (!path_end) 
            { 
                conn_close(c); 
                return; 
            }

            c->keep_alive = (strcasestr(c->req, "Connection: keep-alive") != NULL);

            if (0 != strncmp(c->req, "GET ", 4)) 
            { 
                prepare_error(c, 405, "Method Not Allowed"); 
            } 
            else 
            {
                char u[1024];
                int u_len = (int)(path_end - path_start);
                if (u_len > 1023) 
                {
                    u_len = 1023;
                }
                memcpy(u, path_start, u_len); u[u_len] = 0;

                if (strstr(u, "..")) 
                {
                    prepare_error(c, 403, "Access Denied");
                }
                else 
                {
                    if (0 == strcmp(u, "/")) 
                    {
                        strcpy(u, "/index.html");
                    }
                    zstr path = zfile_join(g_cfg.root, u);
                    prepare_file(c, zstr_cstr(&path));
                    zstr_free(&path);
                }
            }
            struct epoll_event ev = 
            { 
                .events = EPOLLOUT | EPOLLRDHUP | EPOLLET, 
                .data.ptr = c 
            };
            epoll_ctl(t_epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
        }
    }
    
    if (events & EPOLLOUT) 
    {
        if (STATE_WRITE_HEADER == c->state) 
        {
            int n = send(c->fd, c->res_head + c->head_sent, c->head_len - c->head_sent, 0);
            if (n < 0) 
            { 
                if (EAGAIN != errno && EWOULDBLOCK != errno) 
                {
                    conn_close(c); 
                }
                return; 
            }
            c->head_sent += n;
            if (c->head_sent == c->head_len) 
            {
                c->state = (c->file_fd != -1) ? STATE_WRITE_FILE : STATE_CLOSE;
            }
        }
        if (STATE_WRITE_FILE == c->state) 
        {
            ssize_t n = sendfile(c->fd, c->file_fd, &c->file_off, c->file_rem);
            if (n < 0) 
            { 
                if (EAGAIN != errno) 
                {
                    conn_close(c); 
                }
                return; 
            }
            c->file_rem -= n;
            if (0 == c->file_rem) 
            {
                goto finish;
            }
        } 
        else if (STATE_CLOSE == c->state) 
        {
             goto finish;
        }
        return;
    finish:
        if (c->keep_alive) 
        {
            conn_reset(c);
            struct epoll_event ev = 
            { 
                .events = EPOLLIN | EPOLLRDHUP | EPOLLET, 
                .data.ptr = c 
            };
            epoll_ctl(t_epoll_fd, EPOLL_CTL_MOD, c->fd, &ev);
        } 
        else 
        {
            conn_close(c);
        }
    }
}

void* worker_thread_routine(void *arg) 
{
    znet_socket server_sock = *(znet_socket*)arg;
    int raw_server = znet_raw(server_sock);

    t_conns = calloc(MAX_CONNS, sizeof(zconn_t));
    for(int i = 0; i < MAX_CONNS; i++) 
    {
        t_conns[i].fd = -1;
    }
    
    t_epoll_fd = epoll_create1(0);
    struct epoll_event ev = 
    { 
        .events = EPOLLIN, 
        .data.fd = raw_server 
    };
    epoll_ctl(t_epoll_fd, EPOLL_CTL_ADD, raw_server, &ev);
    
    struct epoll_event events[MAX_EVENTS];
    
    while(1) 
    {
        int nfds = epoll_wait(t_epoll_fd, events, MAX_EVENTS, -1); 
        for(int i=0; i<nfds; i++) 
        {
            if (events[i].data.fd == raw_server) 
            {
                while(1) 
                {
                    znet_addr caddr;
                    znet_socket client = znet_accept(server_sock, &caddr);
                    if (!client.valid) 
                    {
                        break;
                    }
                    
                    int cfd = znet_raw(client);
                    if (cfd >= MAX_CONNS) 
                    { 
                        znet_close(&client); 
                        continue; 
                    }
                    
                    znet_set_nonblocking(client, true);
                    int flag=1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &flag, 4);
                    
                    zconn_t *c = &t_conns[cfd];
                    c->fd = cfd; conn_reset(c);
                    
                    struct epoll_event ev = 
                    { 
                        .events = EPOLLIN | EPOLLRDHUP | EPOLLET, 
                        .data.ptr = c 
                    };
                    epoll_ctl(t_epoll_fd, EPOLL_CTL_ADD, cfd, &ev);
                }
            } 
            else 
            { 
                handle_io((zconn_t*)events[i].data.ptr, events[i].events); 
            }
        }
    }
    return NULL;
}

zres server_entry(int argc, char **argv) 
{
    check_sys(znet_init(), "Net init failed");
    
    signal(SIGPIPE, SIG_IGN);

    load_config_files();
    if (argc > 1) 
    {
        strncpy(g_cfg.root, argv[1], 1023);
    }
    
    znet_socket s = znet_socket_create(ZNET_IPV4, ZNET_TCP);
    int opt = 1; 
    setsockopt(znet_raw(s), SOL_SOCKET, SO_REUSEADDR, &opt, 4);
    setsockopt(znet_raw(s), SOL_SOCKET, SO_REUSEPORT, &opt, 4);
    
    znet_addr addr; znet_addr_from_str("0.0.0.0", g_cfg.port, &addr);
    check_sys(znet_bind(s, addr), "Bind failed");
    check_sys(znet_listen(s, 40000), "Listen failed");
    
    znet_set_nonblocking(s, true);
    int workers = get_nprocs();
    
    printf("=> zhttpd-async v1.0 | Port %d | Workers %d | Root: %s\n", g_cfg.port, workers, g_cfg.root);

    pthread_t *threads = malloc(sizeof(pthread_t) * workers);
    for(int i = 0; i < workers; i++) 
    {
        pthread_create(&threads[i], NULL, worker_thread_routine, &s);
    }
    for(int i = 0; i < workers; i++) 
    {
        pthread_join(threads[i], NULL);
    }
    return zres_ok();
}

int main(int c, char **v) 
{ 
    return run(server_entry(c, v)); 
}
