
/* zhttpd.c - v1.1.0 Production
 *
 * Usage:
 *   ./zhttpd [DIR] [PORT] [THREADS]
 *   Example: ./zhttpd . 8080 512
 *
 *  COMPILE:
 *   Linux:   gcc zhttpd.c -o zhttpd -std=c11
 *   Windows: gcc zhttpd.c -o zhttpd.exe -lws2_32 -std=c11
 *
 *  OR BUILD:
 *   Linux: make
 *   Windows: build
*/

#if !defined(_WIN32)
#   define _POSIX_C_SOURCE 200809L
#   define _DEFAULT_SOURCE
#   include <netinet/tcp.h>
#   include <netinet/in.h>
#   include <unistd.h>
#endif

#if defined(_WIN32)
#   define WIN32_LEAN_AND_MEAN
#   include <winsock2.h>
#   define write(fd, buf, len) send(fd, buf, len, 0)
#endif

#define ZERROR_IMPLEMENTATION
#define ZERROR_SHORT_NAMES
#include "zerror.h"

#define ZFILE_IMPLEMENTATION
#include "zfile.h"

#define ZNET_IMPLEMENTATION
#include "znet.h"

#define ZTHREAD_IMPLEMENTATION
#include "zthread.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <string.h>

// Defaults.

#define DEFAULT_PORT 8080
#define DEFAULT_THREADS 128
#define DEFAULT_TIMEOUT 5000
#define DEFAULT_CHUNK 16384
#define MAX_HEADER_SIZE 8192 

// Globals.

int g_port = DEFAULT_PORT;
int g_threads = DEFAULT_THREADS;
int g_timeout = DEFAULT_TIMEOUT;
int g_chunk_size = DEFAULT_CHUNK;
char g_root[1024] = ".";

typedef struct 
{
    znet_socket socket;
    char client_ip[64];
} job_t;

typedef struct 
{
    job_t *queue;
    int head, tail, count, size;
    zmutex_t lock;      
    zcond_t  notify;    
    volatile int running;
} ThreadPool;

ThreadPool pool;

// Signal handler.
void handle_sig(int sig) 
{
    (void)sig;
    
    static time_t last_time = 0;
    time_t now = time(NULL);

    if (now - last_time < 2) 
    {
        pool.running = 0;
        zcond_broadcast(&pool.notify); // Wake up workers.
        
        // Use write() because printf() is unsafe in signal handlers.
        const char msg[] = "\n>>> Shutdown Initiated. Bye!\n";
        write(1, msg, sizeof(msg) - 1);
    } 
    else 
    {
        last_time = now;
        const char msg[] = "\n[?] Press Ctrl+C again to stop server.\n";
        write(1, msg, sizeof(msg) - 1);
    }
}

void load_config(const char *filename) 
{
    if (!zfile_exists(filename)) 
    {
        return;
    }

    printf("Loading config: %s\n", filename);
    
    ZFILE_FOR_EACH_LINE(filename, line) 
    {
        if (line.len == 0 || line.data[0] == '#') 
        {
            continue;
        }
        
        zstr_split_iter it = zstr_split_init(line, "=");
        zstr_view key, val;

        if (zstr_split_next(&it, &key) && zstr_split_next(&it, &val)) 
        {
            if (zstr_view_eq(key, "port"))       zstr_view_to_int(val, &g_port);
            if (zstr_view_eq(key, "threads"))    zstr_view_to_int(val, &g_threads);
            if (zstr_view_eq(key, "timeout"))    zstr_view_to_int(val, &g_timeout);
            if (zstr_view_eq(key, "chunk_size")) zstr_view_to_int(val, &g_chunk_size);
            
            if (zstr_view_eq(key, "root")) 
            {
                int len = (int)val.len;
                if (len > 1023) 
                {
                    len = 1023;
                }
                memcpy(g_root, val.data, len);
                g_root[len] = '\0';
                if (len > 0 && (g_root[len-1] == '\r' || g_root[len-1] == '\n'))
                { 
                    g_root[len-1] = '\0';
                }
            }
        }
    }
}

zres setup_server(znet_socket *out_server, int port) 
{
    check_sys(znet_init(), "Network init failed");

    znet_socket s = znet_socket_create(ZNET_IPV4, ZNET_TCP);
    ensure(s.valid, 1, "Socket creation failed");

    int opt = 1;
#   ifdef _WIN32
    setsockopt((SOCKET)s.handle, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#   else
    setsockopt((int)s.handle, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt));
#   endif

    znet_addr bind_addr;
    znet_addr_from_str("0.0.0.0", port, &bind_addr);
    
    if (znet_bind(s, bind_addr) != Z_OK) 
    {
        return zres_err(zerr_create(2, "Bind failed on port %d", port));
    }

    if (znet_listen(s, 1024) != Z_OK) 
    {
        return zres_err(zerr_create(3, "Listen failed"));
    }

    *out_server = s;
    return zres_ok();
}

const char* get_mime(const char *path) 
{
    zstr_view ext = zfile_ext(path);
    if (zstr_view_eq(ext, ".html")) return "text/html; charset=utf-8"; 
    if (zstr_view_eq(ext, ".css"))  return "text/css";
    if (zstr_view_eq(ext, ".js"))   return "application/javascript";
    if (zstr_view_eq(ext, ".json")) return "application/json";
    if (zstr_view_eq(ext, ".png"))  return "image/png";
    if (zstr_view_eq(ext, ".jpg"))  return "image/jpeg";
    return "application/octet-stream";
}

bool send_all(znet_socket s, const char *buf, size_t len) 
{
    size_t total = 0;
    while (total < len) 
    {
        z_ssize_t n = znet_send(s, buf + total, len - total);
        if (n <= 0) 
        {
            return false;
        }
        total += n;
    }
    return true;
}

void serve_file(znet_socket client, const char *full_path, int status_code, bool keep_alive, char *buffer, size_t buf_len) 
{
    FILE *f = fopen(full_path, "rb");
    if (!f) 
    {
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    zstr header = zstr_init();
    zstr_fmt(&header, 
        "HTTP/1.1 %d %s\r\n"
        "Server: zhttpd/1.1\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: %s\r\n\r\n", 
        status_code, (status_code == 200 ? "OK" : "Not Found"),
        get_mime(full_path), 
        fsize,
        keep_alive ? "keep-alive" : "close");
   
    send_all(client, zstr_cstr(&header), zstr_len(&header));
    zstr_free(&header);

    size_t n;
    while ((n = fread(buffer, 1, buf_len, f)) > 0) 
    {
        if (!send_all(client, buffer, n)) 
        {
            break;
        }
    }
    fclose(f);
}

void send_error_page(znet_socket client, int code, const char *msg, bool keep_alive) 
{
    char body[512];
    int len = snprintf(body, sizeof(body), "<h1>%d %s</h1><p>%s</p>", code, (code==404?"Not Found":"Error"), msg);
    char header[512];
    int hlen = snprintf(header, sizeof(header), 
        "HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n", 
        code, len, keep_alive ? "keep-alive" : "close");
    send_all(client, header, hlen);
    send_all(client, body, len);
}

void handle_request(znet_socket client, const char *client_ip, char *io_buffer, size_t io_size) 
{
    size_t header_limit = io_size > MAX_HEADER_SIZE ? MAX_HEADER_SIZE : io_size;
    znet_set_timeout(client, g_timeout);

    while (1) 
    {
        z_ssize_t received = znet_recv(client, io_buffer, header_limit - 1);
        if (received <= 0) 
        {
            break; 
        }
        io_buffer[received] = '\0';

        bool keep_alive = false;
        if (strstr(io_buffer, "Connection: keep-alive") || strstr(io_buffer, "Connection: Keep-Alive")) 
        {
            keep_alive = true;
        }

        zstr_view req_v = zstr_view_from(io_buffer);
        zstr_split_iter lines = zstr_split_init(req_v, "\r\n");
        zstr_view line;
        if (!zstr_split_next(&lines, &line)) 
        {
            break;
        }

        zstr_split_iter parts = zstr_split_init(line, " ");
        zstr_view method_v, url_v;
        if (!zstr_split_next(&parts, &method_v) || !zstr_split_next(&parts, &url_v)) 
        {
            break;
        }

        if (!zstr_view_eq(method_v, "GET"))
        {
            send_error_page(client, 405, "Only GET supported.", keep_alive);
            if (!keep_alive) break;
            continue;
        }

        zstr url_path = zstr_from_view(url_v);
        zstr fs_path = zfile_join(g_root, zstr_cstr(&url_path));
        zfile_normalize(&fs_path);

        if (zstr_contains(&fs_path, ".."))
        {
            send_error_page(client, 403, "Access Denied", keep_alive);
            zstr_free(&url_path); zstr_free(&fs_path);
            if (!keep_alive) 
            {
                break;
            }
            continue;
        }

        if (zfile_exists(zstr_cstr(&fs_path))) 
        {
            if (zfile_is_dir(zstr_cstr(&fs_path))) 
            {
                size_t url_len = zstr_len(&url_path);
                if (url_len > 0 && zstr_cstr(&url_path)[url_len - 1] != '/') 
                {
                    char header[1024];
                    snprintf(header, sizeof(header), 
                        "HTTP/1.1 301 Moved Permanently\r\nLocation: %s/\r\nContent-Length: 0\r\nConnection: %s\r\n\r\n", 
                        zstr_cstr(&url_path), keep_alive ? "keep-alive" : "close");
                    send_all(client, header, strlen(header));
                    zstr_free(&url_path); zstr_free(&fs_path);
                    if (!keep_alive)
                    {
                        break;
                    }
                    continue;
                }
                zstr index_path = zfile_join(zstr_cstr(&fs_path), "index.html");
                if (zfile_exists(zstr_cstr(&index_path))) 
                {
                    serve_file(client, zstr_cstr(&index_path), 200, keep_alive, io_buffer, io_size);
                } 
                else 
                {
                    send_error_page(client, 403, "Forbidden", keep_alive);
                }
                zstr_free(&index_path);
            } 
            else 
            {
                serve_file(client, zstr_cstr(&fs_path), 200, keep_alive, io_buffer, io_size);
            }
        } 
        else 
        {
            send_error_page(client, 404, "Page Not Found", keep_alive);
        }
        zstr_free(&url_path);
        zstr_free(&fs_path);
        
        if (!keep_alive) 
        {
            break;
        }
    }
}

void worker_routine(void *arg) 
{
    (void)arg;
    char *thread_buffer = (char*)malloc(g_chunk_size);
    if (!thread_buffer) 
    {
        return;
    }

    while (1) 
    {
        job_t job;
        zmutex_lock(&pool.lock); 
        while (pool.count == 0 && pool.running) 
        {
            zcond_wait(&pool.notify, &pool.lock);
        }
        if (!pool.running) 
        { 
            zmutex_unlock(&pool.lock); 
            break; 
        }
        job = pool.queue[pool.head];
        pool.head = (pool.head + 1) % pool.size;
        pool.count--;
        zmutex_unlock(&pool.lock);
        
        handle_request(job.socket, job.client_ip, thread_buffer, g_chunk_size);
        znet_close(&job.socket);
    }
    free(thread_buffer);
}

zres run_server(int argc, char **argv)
{
    load_config("zhttpd.conf");

    if (argc > 1) 
    {
        if (zfile_is_file(argv[1])) 
        {
            load_config(argv[1]);
        }
        else 
        {
            strncpy(g_root, argv[1], sizeof(g_root)-1);
        }
    }
    if (argc > 2) g_port = atoi(argv[2]);
    if (argc > 3) g_threads = atoi(argv[3]);

    if (g_port <= 0)         g_port = 8080;
    if (g_threads < 1)       g_threads = 1;
    if (g_threads > 10000)   g_threads = 10000;
    if (g_chunk_size < 1024) g_chunk_size = 1024;

#   ifdef _WIN32
    signal(SIGINT, handle_sig);
#   else
    struct sigaction sa;
    sa.sa_handler = handle_sig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN); 
#   endif

    znet_socket server;
    check_wrap(setup_server(&server, g_port), "Server setup failed");

    pool.size = g_threads * 4;
    pool.queue = calloc(pool.size, sizeof(job_t));
    ensure(pool.queue != NULL, 4, "Queue alloc failed");
    
    pool.head = 0; pool.tail = 0; pool.count = 0; pool.running = 1;
    zmutex_init(&pool.lock); zcond_init(&pool.notify);

    zthread_t *threads = (zthread_t*)malloc(sizeof(zthread_t) * g_threads);
    ensure(threads != NULL, 4, "Thread alloc failed");

    printf("=> zhttpd v1.9\n");
    printf("   Root:    %s\n", g_root);
    printf("   Port:    %d\n", g_port);
    printf("   Threads: %d\n", g_threads);
    printf("   Chunk:   %d bytes\n", g_chunk_size);

    for (int i = 0; i < g_threads; i++) 
    {
        zthread_create(&threads[i], worker_routine, NULL);
    }

    while (pool.running) 
    {
        znet_addr client_addr;
        znet_socket client = znet_accept(server, &client_addr);
        
        if (!pool.running) 
        {
            break;
        }

        if (client.valid) 
        {
            int flag = 1;
            setsockopt((int)client.handle, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

            zmutex_lock(&pool.lock);
            if (pool.count < pool.size) 
            {
                pool.queue[pool.tail].socket = client;
                znet_addr_to_str(client_addr, pool.queue[pool.tail].client_ip, 64);
                pool.tail = (pool.tail + 1) % pool.size;
                pool.count++;
                zcond_signal(&pool.notify);
            } 
            else 
            {
                znet_close(&client);
            }
            zmutex_unlock(&pool.lock);
        }
    }

    free(threads);
    free(pool.queue);
    znet_close(&server);
    znet_term();
    
    return zres_ok();
}

int main(int argc, char **argv) 
{
    return run(run_server(argc, argv));
}