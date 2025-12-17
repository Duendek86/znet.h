
/* zhttpd.c - v1.0 Production
   
   Features:
     - zerror.h integration for robust startup checks.
     - zmath.h/zrand.h for zero-dependency math/randomness.
     - Thread pool, clean URLs, and atomic logging.

   COMPILE:
     Linux:   gcc zhttpd.c -o zhttpd -std=c11
     Windows: gcc zhttpd.c -o zhttpd.exe -lws2_32 -std=c11
*/

#if !defined(_WIN32)
#   define _POSIX_C_SOURCE 200809L
#   define _DEFAULT_SOURCE
#endif

#if defined(_WIN32)
#   define WIN32_LEAN_AND_MEAN
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
#include <time.h>
#include <signal.h>

// Configuration.
#define SERVER_PORT 8080
#define THREAD_POOL_SIZE 8
#define CHUNK_SIZE 16384     
#define TIMEOUT_MS 5000      
#define MAX_HEADER_SIZE 8192 

// Globals.
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
const char *root_dir = ".";

// Signals.
void handle_sig(int sig) 
{
    (void)sig;
    printf("\n[Server] Stopping...\n");
    pool.running = 0;
    zcond_broadcast(&pool.notify);
}

// This function wraps the dangerous system calls and returns a Result.
zres setup_server(znet_socket *out_server, int port) 
{
    if (znet_init() != 0) 
    {
        return zres_err(zerr_create(1, "Failed to initialize network subsystem (WSAStartup failed?)"));
    }

    znet_socket s = znet_socket_create(ZNET_IPV4, ZNET_TCP);
    if (!s.valid) 
    {
        return zres_err(zerr_errno(errno, "Failed to create TCP socket"));
    }

    int opt = 1;

#   ifdef _WIN32
    if (setsockopt((SOCKET)s.handle, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
#   else
    if (setsockopt((int)s.handle, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt)) < 0) {
#   endif
        // We warn but don't fail hard here, although wrapping it is good practice.
        // return zres_err(zerr_errno(errno, "Failed to set SO_REUSEADDR"));
    }

    znet_addr bind_addr;
    znet_addr_from_str("0.0.0.0", port, &bind_addr);
    
    if (znet_bind(s, bind_addr) != Z_OK) 
    {
        // This is the most common error (Port taken).
        return zres_err(zerr_errno(errno, "Could not bind to port %d", port));
    }

    if (znet_listen(s, 128) != Z_OK) 
    {
        return zres_err(zerr_errno(errno, "Failed to listen on socket"));
    }

    *out_server = s;
    return zres_ok();
}

// Logging.
void access_log(const char *ip, int status, const char *method, const char *path) 
{
    time_t now = time(NULL);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[%s] %s \"%s %s\" %d\n", tbuf, ip, method, path, status);
    fflush(stdout); 
}

// Helpers.
const char* get_mime(const char *path) 
{
    zstr_view ext = zfile_ext(path);
    if (zstr_view_eq(ext, ".html")) return "text/html; charset=utf-8"; 
    if (zstr_view_eq(ext, ".css"))  return "text/css";
    if (zstr_view_eq(ext, ".js"))   return "application/javascript";
    if (zstr_view_eq(ext, ".json")) return "application/json";
    if (zstr_view_eq(ext, ".png"))  return "image/png";
    if (zstr_view_eq(ext, ".jpg"))  return "image/jpeg";
    if (zstr_view_eq(ext, ".svg"))  return "image/svg+xml";
    if (zstr_view_eq(ext, ".ico"))  return "image/x-icon";
    return "application/octet-stream";
}

bool send_all(znet_socket s, const char *buf, size_t len) 
{
    size_t total = 0;
    while (total < len) 
    {
        z_ssize_t n = znet_send(s, buf + total, len - total);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

void serve_file(znet_socket client, const char *full_path, int status_code) 
{
    FILE *f = fopen(full_path, "rb");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    zstr header = zstr_init();
    zstr_fmt(&header, 
        "HTTP/1.1 %d %s\r\n"
        "Server: zhttpd/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n\r\n", 
        status_code, (status_code == 200 ? "OK" : "Not Found"),
        get_mime(full_path), fsize);
   
    fflush(stdout);
    send_all(client, zstr_cstr(&header), zstr_len(&header));
    zstr_free(&header);

    char chunk[CHUNK_SIZE];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) 
    {
        if (!send_all(client, chunk, n)) break;
    }
    fclose(f);
}

void send_error_page(znet_socket client, int code, const char *msg) 
{
    zstr custom_404 = zfile_join(root_dir, "404.html");
    if (code == 404 && zfile_exists(zstr_cstr(&custom_404))) 
    {
        serve_file(client, zstr_cstr(&custom_404), 404);
        zstr_free(&custom_404);
        return;
    }
    zstr_free(&custom_404);

    char body[512];
    int len = snprintf(body, sizeof(body), "<h1>%d %s</h1><p>%s</p><hr><i>zhttpd/1.0</i>", code, (code==404?"Not Found":"Error"), msg);
    char header[512];
    int hlen = snprintf(header, sizeof(header), 
        "HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", code, len);
    send_all(client, header, hlen);
    send_all(client, body, len);
}

// Request handler.
void handle_request(znet_socket client, const char *client_ip) 
{
    char buf[MAX_HEADER_SIZE];
    znet_set_timeout(client, TIMEOUT_MS);

    while (1) 
    {
        z_ssize_t received = znet_recv(client, buf, MAX_HEADER_SIZE - 1);
        if (received <= 0) break;
        buf[received] = '\0';

        zstr_view req_v = zstr_view_from(buf);
        zstr_split_iter lines = zstr_split_init(req_v, "\r\n");
        zstr_view line;
        if (!zstr_split_next(&lines, &line)) break;

        zstr_split_iter parts = zstr_split_init(line, " ");
        zstr_view method_v, url_v;
        if (!zstr_split_next(&parts, &method_v) || !zstr_split_next(&parts, &url_v)) break;

        if (!zstr_view_eq(method_v, "GET")) 
        {
            send_error_page(client, 405, "Only GET supported.");
            access_log(client_ip, 405, "OTHER", "---");
            break;
        }

        zstr url_path = zstr_from_view(url_v);
        zstr fs_path = zfile_join(root_dir, zstr_cstr(&url_path));
        zfile_normalize(&fs_path);

        if (zstr_contains(&fs_path, "..")) 
        {
            send_error_page(client, 403, "Access Denied");
            access_log(client_ip, 403, "GET", zstr_cstr(&url_path));
            zstr_free(&url_path); zstr_free(&fs_path);
            break;
        }

        if (zfile_exists(zstr_cstr(&fs_path))) 
        {
            if (zfile_is_dir(zstr_cstr(&fs_path))) 
            {
                size_t url_len = zstr_len(&url_path);
                if (url_len > 0 && zstr_cstr(&url_path)[url_len - 1] != '/')
                {
                    char loc[1024];
                    snprintf(loc, sizeof(loc), "Location: %s/\r\n", zstr_cstr(&url_path));
        
                    char header[1024];
                    snprintf(header, sizeof(header), 
                        "HTTP/1.1 301 Moved Permanently\r\n"
                        "%s"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n\r\n", loc);
            
                    send_all(client, header, strlen(header));
        
                    // Logging
                    access_log(client_ip, 301, "REDIR", zstr_cstr(&url_path));
        
                    zstr_free(&url_path); zstr_free(&fs_path);
                    return;
                }

                zstr index_path = zfile_join(zstr_cstr(&fs_path), "index.html");
                if (zfile_exists(zstr_cstr(&index_path))) 
                {
                    serve_file(client, zstr_cstr(&index_path), 200);
                    access_log(client_ip, 200, "GET", zstr_cstr(&url_path));
                } 
                else 
                {
                    send_error_page(client, 403, "Directory Listing Forbidden");
                    access_log(client_ip, 403, "GET", zstr_cstr(&url_path));
                }
                zstr_free(&index_path);
            } 
            else 
            {
                serve_file(client, zstr_cstr(&fs_path), 200);
                access_log(client_ip, 200, "GET", zstr_cstr(&url_path));
            }
        } 
        else 
        {
            zstr clean_path = zstr_dup(&fs_path);
            zstr_cat(&clean_path, ".html");
            if (zfile_exists(zstr_cstr(&clean_path))) 
            {
                serve_file(client, zstr_cstr(&clean_path), 200);
                access_log(client_ip, 200, "GET", zstr_cstr(&url_path));
            } 
            else 
            {
                send_error_page(client, 404, "Page Not Found");
                access_log(client_ip, 404, "GET", zstr_cstr(&url_path));
            }
            zstr_free(&clean_path);
        }
        zstr_free(&url_path);
        zstr_free(&fs_path);
    }
}

// Worker.
void worker_routine(void *arg) 
{
    (void)arg;
    while (1) 
    {
        job_t job;
        zmutex_lock(&pool.lock); 
        while (pool.count == 0 && pool.running) zcond_wait(&pool.notify, &pool.lock);
        if (!pool.running) { zmutex_unlock(&pool.lock); break; }
        job = pool.queue[pool.head];
        pool.head = (pool.head + 1) % pool.size;
        pool.count--;
        zmutex_unlock(&pool.lock);
        handle_request(job.socket, job.client_ip);
        znet_close(&job.socket);
    }
}

int main(int argc, char **argv) 
{
    if (argc > 1) root_dir = argv[1];

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    znet_socket server;
    zres res = setup_server(&server, SERVER_PORT);

    if (!res.is_ok) 
    {
        zerr_print(res.err);
        return 1;
    }

    pool.size = 1024;
    pool.queue = calloc(pool.size, sizeof(job_t));
    pool.head = 0; pool.tail = 0; pool.count = 0; pool.running = 1;
    zmutex_init(&pool.lock); zcond_init(&pool.notify);

    zthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) zthread_create(&threads[i], worker_routine, NULL);

    printf("=> zhttpd v1.0\n");
    printf("Serving: %s\n", root_dir);
    printf("Port:    %d\n", SERVER_PORT);

    while (pool.running) 
    {
        znet_addr client_addr;
        znet_socket client = znet_accept(server, &client_addr);
        if (client.valid) 
        {
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
    znet_close(&server);
    znet_term();
    return 0;
}
