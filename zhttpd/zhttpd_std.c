
/* zhttpd_std.c - v1.3.0 Production
 *
 * Usage:
 *   ./zhttpd [DIR]
 *   Example: ./zhttpd_std .
 *
 *  COMPILE:
 *   Linux:   gcc zhttpd_std.c -o zhttpd -std=c11
 *   Windows: gcc zhttpd_std.c -o zhttpd.exe -lws2_32 -std=c11
 *
 *  OR BUILD:
 *   Linux: make
 *   Windows: build
*/

#if defined(_WIN32)
#   include <windows.h>
#   define MOD_HANDLE HMODULE
#   define MOD_OPEN(path) LoadLibrary(path)
#   define MOD_SYM(h, name) GetProcAddress(h, name)
#   define MOD_CLOSE(h) FreeLibrary(h)
#   define MOD_EXT ".dll"
#else
#   ifdef __linux__
#       include <sys/sendfile.h>
#       include <netinet/tcp.h>
#   endif
#   include <dlfcn.h>
#   include <unistd.h>
#   define MOD_HANDLE void*
#   define MOD_OPEN(path) dlopen(path, RTLD_NOW | RTLD_LOCAL)
#   define MOD_SYM(h, name) dlsym(h, name)
#   define MOD_CLOSE(h) dlclose(h)
#   define MOD_EXT ".so"
#endif

#define ZERROR_IMPLEMENTATION
#define ZERROR_SHORT_NAMES
#include "zerror.h"

#define ZFILE_IMPLEMENTATION
#include "zfile.h"

#define ZSTR_IMPLEMENTATION
#include "zstr.h"

#define ZNET_IMPLEMENTATION
#include "znet.h"

#define ZTHREAD_IMPLEMENTATION
#define ZTHREAD_SHORT_NAMES
#include "zthread.h"

#include "zmodule.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#ifdef ZHTTPD_DEBUG
#   define LOG(...)                     \
    do                                  \
    {                                   \
        printf("[LOG] " __VA_ARGS__);   \
    } while(0)
#else
#   define LOG(...) \
    do              \
    {               \
        /* Lol.*/   \
    } while(0)
#endif

#define INFO(...)               \
do                              \
{                               \
    printf("=> " __VA_ARGS__);  \
} while(0)

#define ERR(...)                            \
do                                          \
{                                           \
    fprintf(stderr, "[ERR] " __VA_ARGS__);  \
} while(0)

// Definitions.

#define MAX_HEADER_SIZE 8192
#define MAX_MODULES 64
#define MAX_MIME_TYPES 128

typedef struct 
{
    int port;
    int threads;
    char root[1024];
    int timeout_ms;
} ServerConfig;

typedef struct 
{
    char ext[32];
    char type[128];
} MimeEntry;

// Globals.
ServerConfig g_config = 
{ 
    .port = 8080,
    .threads = 128,
    .root = ".",
    .timeout_ms = 5000
};

static MOD_HANDLE g_module_handles[MAX_MODULES]; 
static zmodule_def *g_modules[MAX_MODULES + 1]; 
static int g_mod_count = 0;

static MimeEntry g_mimes[MAX_MIME_TYPES];
static int g_mime_count = 0;

static char g_date_header[64];
static time_t g_last_date = 0;
static zmutex_t g_date_lock;
static volatile int g_running = 1;

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
    zcond_t notify; 
    volatile int running; 
} ThreadPool;

ThreadPool pool;

// Helper functions.

static void update_date(void) 
{
    time_t now = time(NULL);
    if (now != g_last_date) 
    {
        zmutex_lock(&g_date_lock);
        if (now != g_last_date) 
        {
            struct tm tm;
#           ifdef _WIN32
            gmtime_s(&tm, &now);
#           else
            gmtime_r(&now, &tm);
#           endif
            strftime(g_date_header, sizeof(g_date_header), "Date: %a, %d %b %Y %H:%M:%S GMT\r\n", &tm);
            g_last_date = now;
        }
        zmutex_unlock(&g_date_lock);
    }
}

static void load_mime_types(const char *path) 
{
    if (!zfile_exists(path)) 
    {
        LOG("No mime.conf found at '%s', using defaults.\n", path);
        strcpy(g_mimes[0].ext, ".html"); 
        strcpy(g_mimes[0].type, "text/html; charset=utf-8");
        strcpy(g_mimes[1].ext, ".css");  
        strcpy(g_mimes[1].type, "text/css");
        strcpy(g_mimes[2].ext, ".js");   
        strcpy(g_mimes[2].type, "application/javascript");
        strcpy(g_mimes[3].ext, ".json"); 
        strcpy(g_mimes[3].type, "application/json");
        g_mime_count = 4;
        return;
    }

    LOG("Loading MIME config: %s\n", path);
    ZFILE_FOR_EACH_LINE(path, line) 
    {
        if (0 == line.len || '#' == line.data[0]) 
        {
            continue;
        }
        
        zstr_split_iter it = zstr_split_init(line, "=");
        zstr_view ext, type;
        
        if (zstr_split_next(&it, &ext) && 
            zstr_split_next(&it, &type)) 
        {
            ext = zstr_view_trim(ext);
            type = zstr_view_trim(type);
            
            if (g_mime_count < MAX_MIME_TYPES) 
            {
                snprintf(g_mimes[g_mime_count].ext, 32, "%.*s", (int)ext.len, ext.data);
                snprintf(g_mimes[g_mime_count].type, 128, "%.*s", (int)type.len, type.data);
                g_mime_count++;
            }
        }
    }
}

static const char* get_mime_type(const char *path) 
{
    zstr_view ext = zfile_ext(path);
    
    for (int i = 0; i < g_mime_count; i++) 
    {
        if (zstr_view_eq(ext, g_mimes[i].ext)) 
        {
            return g_mimes[i].type;
        }
    }
    
    return "application/octet-stream";
}

// Loading logic.

#if defined(_WIN32)
#   include <windows.h>
#   define MOD_HANDLE HMODULE
#   define MOD_OPEN(path) LoadLibrary(path)
#   define MOD_SYM(h, name) GetProcAddress(h, name)
#   define MOD_CLOSE(h) FreeLibrary(h)
#else
#   include <dlfcn.h>
#   include <unistd.h>
#   define MOD_HANDLE void*
#   define MOD_OPEN(path) dlopen(path, RTLD_NOW | RTLD_LOCAL)
#   define MOD_SYM(h, name) dlsym(h, name)
#   define MOD_CLOSE(h) dlclose(h)
#endif

static void load_module(const char *path) 
{
    if (g_mod_count >= MAX_MODULES) 
    {
        return;
    }
    MOD_HANDLE handle = MOD_OPEN(path);
    if (!handle) 
    {
        ERR("Failed to load module '%s'\n", path);
        return; 
    }
    zmodule_def *mod = (zmodule_def*)MOD_SYM(handle, Z_MODULE_ENTRY_SYM);
    if (!mod) 
    { 
        ERR("No Symbol in: %s\n", path); 
        MOD_CLOSE(handle); 
        return; 
    }
    g_module_handles[g_mod_count] = handle;
    g_modules[g_mod_count] = mod;
    g_modules[++g_mod_count] = NULL;
    
    LOG("Loaded Module: %s (%s)\n", mod->name, path);
}

static void load_modules_from_conf(const char *conf_path) 
{
    if (!zfile_exists(conf_path)) 
    {
        return;
    }
    LOG("Reading modules from: %s\n", conf_path);
    ZFILE_FOR_EACH_LINE(conf_path, line) 
    {
        zstr_view v = zstr_view_trim(line);
        if (zstr_view_starts_with(v, "load ")) 
        {
            char path[256]; 
            zstr_view p = zstr_sub(v, 5, v.len - 5); 
            memcpy(path, p.data, p.len); path[p.len] = 0;
            load_module(path);
        }
    }
}

static void load_config_file(const char *path) 
{
    if (!zfile_exists(path)) 
    {
        return;
    }
    LOG("Loading config: %s\n", path);
    ZFILE_FOR_EACH_LINE(path, line) 
    {
        if (0 == line.len || '#' == line.data[0]) 
        {
            continue;
        }
        zstr_split_iter it = zstr_split_init(line, "=");
        zstr_view key, val;
        if (zstr_split_next(&it, &key) && 
            zstr_split_next(&it, &val)) 
        {
            key = zstr_view_trim(key); val = zstr_view_trim(val);
            if (zstr_view_eq(key, "port"))
            {
                zstr_view_to_int(val, &g_config.port);
            }
            if (zstr_view_eq(key, "threads")) 
            {
                zstr_view_to_int(val, &g_config.threads);
            }
            if (zstr_view_eq(key, "root")) 
            {
                int len = (int)val.len < 1023 ? (int)val.len : 1023;
                memcpy(g_config.root, val.data, len); g_config.root[len] = 0;
            }
        }
    }
}

// Request handling.

static void send_error(znet_socket client, int code, const char *msg, bool keep) 
{
    update_date();
    zstr body = zstr_init();
    zstr_fmt(&body, "<h1>%d %s</h1><hr>zhttpd/1.3", code, msg);

    zstr head = zstr_init();
    zstr_fmt(&head, "HTTP/1.1 %d %s\r\nServer: zhttpd/1.3\r\n%sContent-Length: %zu\r\nConnection: %s\r\n\r\n", 
        code, msg, g_date_header, zstr_len(&body), keep ? "keep-alive" : "close");
    
    znet_send(client, zstr_cstr(&head), zstr_len(&head));
    znet_send(client, zstr_cstr(&body), zstr_len(&body));
    zstr_free(&body); 
    zstr_free(&head);
}

static void serve_file(znet_socket client, const char *path, bool keep) 
{
    FILE *f = fopen(path, "rb");
    if (!f) 
    {
        LOG("File Not Found: %s\n", path);
        send_error(client, 404, "Not Found", keep); 
        return; 
    }
    fseek(f, 0, SEEK_END); 
    long fsize = ftell(f); 
    rewind(f);

    update_date();
    
    zstr head = zstr_init();
    zstr_fmt(&head, "HTTP/1.1 200 OK\r\nServer: zhttpd/1.3\r\n%sContent-Type: %s\r\nContent-Length: %ld\r\nConnection: %s\r\n\r\n", 
        g_date_header, get_mime_type(path), fsize, keep ? "keep-alive" : "close");

    znet_send(client, zstr_cstr(&head), zstr_len(&head));
    zstr_free(&head);

#   ifdef __linux__
    // Zero-copy on Linux.
    int fd = fileno(f);
    off_t offset = 0;
    ssize_t sent;
    while (offset < fsize) 
    {
        sent = sendfile((int)client.handle, fd, &offset, fsize - offset);
        if (sent <= 0) 
        {
            if (EINTR == errno) 
            {
                continue;
            }
            if (EAGAIN == errno) 
            {
                break;
            }
            break;
        }
    }
#   else
    char buf[16384];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) 
    { 
        if (znet_send(client, buf, n) <= 0) 
        {
            break; 
        }
    }
#   endif

    fclose(f);
}

static void handle_request(znet_socket client, const char *ip_str) 
{
    znet_set_timeout(client, g_config.timeout_ms);
    zstr buf = zstr_with_capacity(MAX_HEADER_SIZE); 
    
    while (1) 
    {
        zstr_clear(&buf);
        z_ssize_t received = znet_recv(client, zstr_data(&buf), MAX_HEADER_SIZE - 1);
        if (received <= 0) 
        {
            break;
        }
        
        buf.is_long ? (buf.l.len = received) : (buf.s.len = received);
        zstr_data(&buf)[received] = '\0';
        
        zstr_view full_req = zstr_as_view(&buf);
        bool keep = zstr_contains(&buf, "Connection: keep-alive");
        
        zstr_split_iter it = zstr_split_init(full_req, "\r\n");
        zstr_view line;
        if (!zstr_split_next(&it, &line)) 
        {
            break;
        }
        
        zstr_split_iter line_it = zstr_split_init(line, " ");
        zstr_view method, path;
        if (!zstr_split_next(&line_it, &method) || 
            !zstr_split_next(&line_it, &path)) 
        {
            break;
        }
        
        LOG("Request: %.*s %.*s (from %s)\n", (int)method.len, method.data, (int)path.len, path.data, ip_str);

        bool handled = false;
        zstr_view ip_view = zstr_view_from(ip_str);
        for (int i = 0; NULL != g_modules[i]; i++) 
        {
            if (g_modules[i]->handler(client, method, path, full_req, ip_view)) 
            {
                LOG("Module '%s' handled request\n", g_modules[i]->name);
                handled = true; 
                break; 
            }
        }
        if (handled) 
        { 
            if (!keep) 
            {
                break; 
            }
            continue; 
        }

        if (!zstr_view_eq(method, "GET")) 
        { 
            send_error(client, 405, "Method Not Allowed", keep); 
            break; 
        }
        if (zstr_view_eq(path, "/") || 
            zstr_view_eq(path, "")) 
        {
            path = ZSV("/index.html");
        }
        
        char path_cstr[1024];
        snprintf(path_cstr, sizeof(path_cstr), "%.*s", (int)path.len, path.data);
        if (strstr(path_cstr, "..")) 
        { 
            send_error(client, 403, "Access Denied", keep); 
            break; 
        }
        
        zstr full = zfile_join(g_config.root, path_cstr);
        
        LOG("Serving: %s\n", zstr_cstr(&full));
        serve_file(client, zstr_cstr(&full), keep);
        zstr_free(&full);
        
        if (!keep) 
        {
            break;
        }
    }
    zstr_free(&buf);
    znet_close(&client);
}

static void worker(void *arg) 
{
    (void)arg;
    while (1) 
    {
        zmutex_lock(&pool.lock);
        while (0 == pool.count && pool.running) 
        {
            zcond_wait(&pool.notify, &pool.lock);
        }
        if (!pool.running) 
        { 
            zmutex_unlock(&pool.lock); 
            break; 
        }
        job_t job = pool.queue[pool.head];
        pool.head = (pool.head + 1) % pool.size;
        pool.count--;
        zmutex_unlock(&pool.lock);
        handle_request(job.socket, job.client_ip);
    }
}

zres server_entry(int argc, char **argv) 
{
    check_sys(znet_init(), "Net init fail");
    load_mime_types("mime.conf");
    load_modules_from_conf("modules.conf");
    load_config_file("zhttpd.conf");
    
    if (argc > 1) 
    {
        strncpy(g_config.root, argv[1], 1023);
    }
    pool.size = g_config.threads * 4;
    pool.queue = calloc(pool.size, sizeof(job_t));
    pool.running = 1;
    zmutex_init(&pool.lock); zcond_init(&pool.notify); zmutex_init(&g_date_lock);
    update_date();
    
    INFO("zhttpd v1.3\n");
    INFO("Root: %s\n", g_config.root);
    INFO("Port: %d\n", g_config.port);
    
    for(int i = 0; i < g_config.threads; i++) 
    { 
        zthread_t t; 
        zthread_create(&t, worker, NULL); 
        zthread_detach(t); 
    }
    znet_socket s = znet_socket_create(ZNET_IPV4, ZNET_TCP);
    znet_addr a; 
    znet_addr_from_str("0.0.0.0", g_config.port, &a);
    int opt = 1; 
    setsockopt((int)s.handle, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, 4);
    if (Z_OK != znet_bind(s, a) || 
        Z_OK != znet_listen(s, 10000)) 
        {
            return zres_err(zerr_create(1, "Bind failed"));
        }
    while (g_running) 
    {
        znet_addr caddr; 
        znet_socket c = znet_accept(s, &caddr);
        if (!c.valid) 
        {
            continue;
        }
        int flag = 1;
        setsockopt((int)c.handle, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
        zmutex_lock(&pool.lock);
        if (pool.count < pool.size) 
        {
            pool.queue[pool.tail].socket = c;
            znet_addr_to_str(caddr, pool.queue[pool.tail].client_ip, 64);
            pool.tail = (pool.tail + 1) % pool.size;
            pool.count++;
            zcond_signal(&pool.notify);
        } 
        else 
        {
            znet_close(&c);
        }
        zmutex_unlock(&pool.lock);
    }
    znet_close(&s); 
    return zres_ok();
}

void sig(int s) 
{ 
    (void)s; 
    g_running = 0; 
    exit(0); 
}

int main(int c, char **v) 
{ 
    signal(SIGINT, sig); 
    return run(server_entry(c, v)); 
}
