
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

// Configuration.

#define MAX_HEADER_SIZE 8192
#define MAX_MODULES 64
#define MAX_MIME_TYPES 256

typedef struct 
{
    char ext[16];
    char type[128];
} MimeEntry;

struct GlobalConfig 
{
    int port;
    int threads;
    char root[1024];
    int timeout_ms;
    int cache_enabled;
    // MIME.
    MimeEntry mimes[MAX_MIME_TYPES];
    int mime_count;
    // Modules.
    MOD_HANDLE mod_handles[MAX_MODULES];
    zmodule_def *modules[MAX_MODULES + 1];
    int mod_count;
    // State
    volatile int running;
} g_cfg = 
{ 
    .port = 8080, 
    .threads = 128, 
    .root = ".", 
    .timeout_ms = 5000, 
    .cache_enabled = 1 
};

// Date caching.
static char g_date_header[64];
static time_t g_last_date = 0;
static zmutex_t g_date_lock;

static __thread char t_io_buf[MAX_HEADER_SIZE];

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
} ThreadPool;

ThreadPool pool;

// Config loaders.

static void load_config_files(void) 
{
    // Main config.
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
            zstr_view key, val;
            if (zstr_split_next(&it, &key) && 
                zstr_split_next(&it, &val)) 
            {
                key = zstr_view_trim(key); 
                val = zstr_view_trim(val);
                if (zstr_view_eq(key, "port")) 
                {
                    zstr_view_to_int(val, &g_cfg.port);
                }
                if (zstr_view_eq(key, "threads")) 
                {
                    zstr_view_to_int(val, &g_cfg.threads);
                }
                if (zstr_view_eq(key, "root")) 
                {
                    snprintf(g_cfg.root, 1023, "%.*s", (int)val.len, val.data);
                }
                if (zstr_view_eq(key, "timeout")) 
                {
                    zstr_view_to_int(val, &g_cfg.timeout_ms);
                }
                if (zstr_view_eq(key, "cache_enabled")) 
                {
                    zstr_view_to_int(val, &g_cfg.cache_enabled);
                }
            }
        }
    }

    // MIME types.
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
    else 
    {
        // Fallbacks.
        strcpy(g_cfg.mimes[0].ext, ".html"); 
        strcpy(g_cfg.mimes[0].type, "text/html");
        g_cfg.mime_count = 1;
    }

    // Modules.
    if (zfile_exists("modules.conf")) 
    {
        ZFILE_FOR_EACH_LINE("modules.conf", line) 
        {
            zstr_view v = zstr_view_trim(line);
            if (0 == v.len || '#' == v.data[0]) 
            {
                continue;
            }
            if (zstr_view_starts_with(v, "load ")) 
            {
                if (g_cfg.mod_count >= MAX_MODULES) 
                {
                    continue;
                }
                char path[256];
                zstr_view p = zstr_sub(v, 5, v.len - 5);
                p = zstr_view_trim(p);
                snprintf(path, 255, "%.*s", (int)p.len, p.data);
                
                MOD_HANDLE h = MOD_OPEN(path);
                if (h) 
                {
                    zmodule_def *mod = (zmodule_def*)MOD_SYM(h, Z_MODULE_ENTRY_SYM);
                    if (mod) 
                    {
                        g_cfg.mod_handles[g_cfg.mod_count] = h;
                        g_cfg.modules[g_cfg.mod_count++] = mod;
                        printf(" [MOD] Loaded: %s\n", mod->name);
                    } 
                    else 
                    { 
                        MOD_CLOSE(h); printf(" [MOD] Error: Symbol missing in %s\n", path); }
                } 
                else 
                { 
                    printf(" [MOD] Error: Failed to open %s\n", path); 
                }
            }
        }
    }
    g_cfg.modules[g_cfg.mod_count] = NULL;
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

// Server logic.

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

static void send_raw(znet_socket c, const char *data, size_t len) 
{
    size_t total = 0;
    while(total < len) 
    {
        z_ssize_t n = znet_send(c, data + total, len - total);
        if(n <= 0) 
        {
            break;
        }
        total += n;
    }
}

static void send_resp(znet_socket c, int code, const char *msg, const char *ctype, long len, bool keep) 
{
    update_date();
    char head[1024];
    int hlen = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\n"
        "Server: zhttpd/1.3\r\n"
        "%s"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: %s\r\n\r\n",
        code, msg, g_date_header, ctype, len, keep ? "keep-alive" : "close");
    send_raw(c, head, hlen);
}

static void serve_file(znet_socket client, const char *path, bool keep) 
{
    FILE *f = fopen(path, "rb");
    if (!f) 
    { 
        const char *body = "<h1>404 Not Found</h1>";
        send_resp(client, 404, "Not Found", "text/html", strlen(body), keep);
        send_raw(client, body, strlen(body));
        return; 
    }

    fseek(f, 0, SEEK_END); long fsize = ftell(f); rewind(f);
    send_resp(client, 200, "OK", get_mime(path), fsize, keep);

#   ifdef __linux__
    int fd = fileno(f);
    off_t offset = 0;
    while (offset < fsize) 
    {
        ssize_t sent = sendfile((int)client.handle, fd, &offset, fsize - offset);
        if (sent <= 0) 
        {
            break;
        }
    }
#   else
    size_t n;
    while ((n = fread(t_io_buf, 1, MAX_HEADER_SIZE, f)) > 0) 
    { 
        if (znet_send(client, t_io_buf, n) <= 0) 
        {
            break; 
        }
    }
#   endif
    fclose(f);
}

static void handle_request(znet_socket client, const char *ip_str) 
{
    znet_set_timeout(client, g_cfg.timeout_ms);
    while (1) 
    {
        z_ssize_t received = znet_recv(client, t_io_buf, MAX_HEADER_SIZE - 1);
        if (received <= 0) 
        {
            break;
        }
        t_io_buf[received] = '\0';
        
        // Keep original request for modules (BEFORE parsing modifies it)
        char original_buf[MAX_HEADER_SIZE];
        memcpy(original_buf, t_io_buf, received + 1);
        zstr_view full_req = {original_buf, (size_t)received};
        
        bool keep = strstr(t_io_buf, "Connection: keep-alive") != NULL;
        
        char *method_end = strchr(t_io_buf, ' ');
        if (!method_end) 
        {
            break;
        }
        *method_end = '\0';
        
        char *path_start = method_end + 1;
        char *path_end = strchr(path_start, ' ');
        if (!path_end) 
        {
            break;
        }
        *path_end = '\0';
        
        zstr_view method = {t_io_buf, (size_t)(method_end - t_io_buf)};
        zstr_view path   = {path_start, (size_t)(path_end - path_start)};
        zstr_view ip     = zstr_view_from(ip_str);
        
        bool handled = false;
        for (int i = 0; g_cfg.modules[i]; i++) 
        {
            if (g_cfg.modules[i]->handler(client, method, path, full_req, ip)) 
            {
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

        if (0 != strcmp(t_io_buf, "GET")) 
        { 
             const char *b = "Method Not Allowed";
             send_resp(client, 405, b, "text/plain", strlen(b), keep);
             send_raw(client, b, strlen(b));
             break; 
        }

        if (strstr(path_start, "..")) 
        { 
             const char *b = "Access Denied";
             send_resp(client, 403, b, "text/plain", strlen(b), keep);
             send_raw(client, b, strlen(b));
             break; 
        }
        
        if (0 == strcmp(path_start, "/")) 
        {
            path_start = "/index.html";
        }
        
        zstr full = zfile_join(g_cfg.root, path_start);
        serve_file(client, zstr_cstr(&full), keep);
        zstr_free(&full);
        
        if (!keep) 
        {
            break;
        }
    }
    znet_close(&client);
}

static void clean_worker(void *arg) { (void)arg; } // placeholder if needed? No.

static void unload_modules(void) {
    for (int i = 0; i < g_cfg.mod_count; i++) {
        if (g_cfg.mod_handles[i]) {
            MOD_CLOSE(g_cfg.mod_handles[i]);
            g_cfg.mod_handles[i] = NULL;
        }
        g_cfg.modules[i] = NULL;
    }
    g_cfg.mod_count = 0;
    printf(" [SYS] Modules unloaded.\n");
}

static void worker(void *arg) 
{
    (void)arg;
    while (1) 
    {
        zmutex_lock(&pool.lock);
        while (0 == pool.count && g_cfg.running) 
        {
            zcond_wait(&pool.notify, &pool.lock);
        }
        if (!g_cfg.running) 
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
    load_config_files();
    
    if (argc > 1) 
    {
        strncpy(g_cfg.root, argv[1], 1023);
    }
    
    pool.size = g_cfg.threads * 4;
    pool.queue = calloc(pool.size, sizeof(job_t));
    g_cfg.running = 1;
    zmutex_init(&pool.lock); 
    zcond_init(&pool.notify); 
    zmutex_init(&g_date_lock);
    update_date();
    
    printf("=> zhttpd v1.3 [STD] | Port: %d | Threads: %d | Root: %s\n", g_cfg.port, g_cfg.threads, g_cfg.root);
    printf("   MIME: %d types loaded | Modules: %d loaded\n", g_cfg.mime_count, g_cfg.mod_count);
    
    for(int i = 0; i < g_cfg.threads; i++) 
    { 
        zthread_t t; 
        zthread_create(&t, worker, NULL); 
        zthread_detach(t); 
    }
    
    znet_socket s = znet_socket_create(ZNET_IPV4, ZNET_TCP);
    znet_addr a; 
    znet_addr_from_str("0.0.0.0", g_cfg.port, &a);
    int opt = 1; 
    setsockopt((int)s.handle, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, 4);
    
    check_sys(znet_bind(s, a), "Bind failed");
    check_sys(znet_listen(s, 10000), "Listen failed");
    
    while (g_cfg.running) 
    {
        // Check for restart signal
        if (zfile_exists(".restart")) {
             printf(" [SYS] Restart triggered.\n");
             remove(".restart");
             
             // Accept and close the dummy connection that triggered this
             znet_addr dummy_addr;
             znet_socket dummy_conn = znet_accept(s, &dummy_addr);
             if (dummy_conn.valid) {
                 znet_close(&dummy_conn);
             }
             
             // Now safe to unload and reload
             unload_modules();
             load_config_files();
             printf(" [SYS] Reload complete.\n");
             continue;
        }

        znet_addr caddr; znet_socket c = znet_accept(s, &caddr);
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
    
    unload_modules(); // Cleanup on exit
    return zres_ok();
}

int main(int c, char **v) 
{ 
    return run(server_entry(c, v)); 
}

