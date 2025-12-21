#include "../zmodule.h"
#include "../zfile.h"
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define ATOMIC_INCREMENT(x) InterlockedIncrement((LONG*)&(x))
#define ATOMIC_ADD(x, val) InterlockedAdd((LONG*)&(x), (LONG)(val))
#else
#include <dlfcn.h>
#define ATOMIC_INCREMENT(x) __sync_add_and_fetch(&(x), 1)
#define ATOMIC_ADD(x, val) __sync_add_and_fetch(&(x), val)
#endif

#define HISTORY_SIZE 60
#define AUTH_HEADER "Authorization: Basic YWRtaW46c3RhdHMxMjM="  // admin:stats123

// Statistics data structure
typedef struct {
    unsigned long long total_requests;
    unsigned long long total_bytes_sent;
    unsigned int active_clients;
    unsigned long long response_times_sum;  // in MICROSECONDS (us)
    time_t start_time;
    time_t last_reset;
    
    // Content type counters (32-bit for atomic compatibility)
    unsigned long req_html;
    unsigned long req_js;
    unsigned long req_css;
    unsigned long req_img;
    unsigned long req_api;
    unsigned long req_other;
} stats_current;

typedef struct {
    time_t timestamp;
    unsigned int requests_per_sec;
    unsigned int clients;
    unsigned int avg_response_us; // in MICROSECONDS (us)
    unsigned long bytes_sent;
} stats_snapshot;

// Global statistics
static stats_current g_dashboard = {0};
static stats_snapshot g_history[HISTORY_SIZE] = {0};
static int g_history_index = 0;
static time_t g_last_snapshot = 0;

// Client tracking for "Active Clients" estimation
// Simple hash-based tracking of recent activity
#define MAX_TRACKED_CLIENTS 256
static time_t client_last_seen[MAX_TRACKED_CLIENTS] = {0};

static char g_session_token[64] = {0};

// Initialize dashboard stats on first load
static void init_dashboard(void) {
    static int initialized = 0;
    if (!initialized) {
        g_dashboard.start_time = time(NULL);
        g_dashboard.last_reset = g_dashboard.start_time;
        g_last_snapshot = g_dashboard.start_time;
        
        // Load or Generate Session Token
        FILE *token_file = fopen(".session_token", "r");
        if (token_file) {
            // Load existing token
            if (fgets(g_session_token, sizeof(g_session_token), token_file)) {
                // Remove newline if present
                size_t len = strlen(g_session_token);
                if (len > 0 && g_session_token[len-1] == '\n') {
                    g_session_token[len-1] = '\0';
                }
            }
            fclose(token_file);
        }
        
        // If no token loaded or file didn't exist, generate new one
        if (g_session_token[0] == '\0') {
            srand((unsigned int)time(NULL));
            const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            for(int i=0; i<32; i++) {
                g_session_token[i] = chars[rand() % 62];
            }
            g_session_token[32] = '\0';
            
            // Save token to file
            token_file = fopen(".session_token", "w");
            if (token_file) {
                fprintf(token_file, "%s\n", g_session_token);
                fclose(token_file);
            }
        }
        
        initialized = 1;
    }
}

// Update snapshot for historical data
static void update_snapshot(void) {
    time_t now = time(NULL);
    if (now - g_last_snapshot < 1) return;  // Update every 1 second
    
    g_history_index = (g_history_index + 1) % HISTORY_SIZE;
    
    // Calculate deltas
    static unsigned long long last_requests = 0;
    static unsigned long long last_bytes = 0;
    static unsigned long long last_response_sum = 0;
    
    unsigned long long current_requests = g_dashboard.total_requests;
    unsigned long long current_bytes = g_dashboard.total_bytes_sent;
    unsigned long long current_response_sum = g_dashboard.response_times_sum;
    
    unsigned long long delta_requests = current_requests - last_requests;
    unsigned long long delta_bytes = current_bytes - last_bytes;
    unsigned long long delta_response = current_response_sum - last_response_sum;
    
    // Update statics for next time
    last_requests = current_requests;
    last_bytes = current_bytes;
    last_response_sum = current_response_sum;
    
    g_history[g_history_index].timestamp = now;
    
    // Estimate active clients by counting unique IPs seen in last 5 seconds
    unsigned int active_count = 0;
    time_t threshold = now - 5;
    for (int i = 0; i < MAX_TRACKED_CLIENTS; i++) {
        if (client_last_seen[i] > threshold) {
            active_count++;
        }
    }
    
    g_dashboard.active_clients = active_count;
    g_history[g_history_index].clients = g_dashboard.active_clients;
    
    g_history[g_history_index].bytes_sent = (unsigned long)(delta_bytes / 1024);  // KB in this second
    
    // Requests per second for this interval
    g_history[g_history_index].requests_per_sec = (unsigned int)delta_requests;
    
    // Calculate average response time for THIS interval in MICROSECONDS
    if (delta_requests > 0) {
        // use delta so we see the average for this second, not all time
        g_history[g_history_index].avg_response_us = 
            (unsigned int)(delta_response / delta_requests);
    } else {
        g_history[g_history_index].avg_response_us = 0;
    }
    
    g_last_snapshot = now;
}

// Get current time in microseconds (high resolution)
static unsigned long long get_time_us(void) {
#ifdef _WIN32
    static LARGE_INTEGER frequency = {0};
    LARGE_INTEGER counter;
    
    if (frequency.QuadPart == 0) {
        QueryPerformanceFrequency(&frequency);
    }
    
    QueryPerformanceCounter(&counter);
    return (unsigned long long)((counter.QuadPart * 1000000) / frequency.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)(ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
#endif
}

// Track request start (called at beginning of request)
static unsigned long long request_start_time = 0;

static uint32_t hash_ip(zstr_view ip) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < ip.len; i++) {
        hash = ((hash << 5) + hash) + ip.data[i];
    }
    return hash;
}

// Track a request with real timing and content type
static void track_request(unsigned long bytes_sent, unsigned long long response_time_us, zstr_view path, zstr_view ip) {
    ATOMIC_INCREMENT(g_dashboard.total_requests);
    ATOMIC_ADD(g_dashboard.total_bytes_sent, bytes_sent);
    
    // Update active client tracker
    if (ip.len > 0) {
        uint32_t h = hash_ip(ip);
        client_last_seen[h % MAX_TRACKED_CLIENTS] = time(NULL);
    }
    
    // Track content type
    if (zstr_view_ends_with(path, ".html")) ATOMIC_INCREMENT(g_dashboard.req_html);
    else if (zstr_view_ends_with(path, ".js")) ATOMIC_INCREMENT(g_dashboard.req_js);
    else if (zstr_view_ends_with(path, ".css")) ATOMIC_INCREMENT(g_dashboard.req_css);
    else if (zstr_view_ends_with(path, ".png") || zstr_view_ends_with(path, ".jpg") || 
             zstr_view_ends_with(path, ".ico") || zstr_view_ends_with(path, ".svg")) 
             ATOMIC_INCREMENT(g_dashboard.req_img);
    else if (zstr_view_starts_with(path, "/api/")) ATOMIC_INCREMENT(g_dashboard.req_api);
    else ATOMIC_INCREMENT(g_dashboard.req_other);
    
    // Track microseconds directly
    ATOMIC_ADD(g_dashboard.response_times_sum, response_time_us);
    
    update_snapshot();
}

static bool check_basic_auth(zstr_view req) {
    // Relaxed check: just look for the base64 token
    // We need to ensure we are checking the actual data
    if (req.len > 0 && req.data) {
        if (strstr(req.data, "YWRtaW46c3RhdHMxMjM=")) {
            return true;
        }
    }
    
    // Debug logging
    FILE *f = fopen("auth_debug.log", "a");
    if (f) {
        fprintf(f, "[AuthFail] Request did not contain expected token.\n");
        // Dump first 200 chars of request
        if (req.data) {
            fprintf(f, "Headers snippet: %.200s\n", req.data);
        } else {
             fprintf(f, "Headers snippet: (null)\n");
        }
        fclose(f);
    }
    
    return false;
}

// Check authentication - Basic Auth AND Session Token
static bool check_full_auth(zstr_view req) {
    // 1. Basic Auth
    if (!check_basic_auth(req)) return false;
    
    // 2. Session Token
    char token_header[128];
    snprintf(token_header, sizeof(token_header), "X-Dashboard-Token: %s", g_session_token);
    
    // Check if token header is present
    if (!strstr(req.data, token_header)) {
        return false;
    }
    
    return true;
}

static bool check_auth(zstr_view req) {
    return check_full_auth(req);
}


// Send JSON response
static void send_json(znet_socket c, int code, const char *json) {
    // Use zstr_view to get length
    zstr_view json_view = {.data = json, .len = 0};
    while (json[json_view.len]) json_view.len++;
    
    zstr h = zstr_init();
    zstr_fmt(&h, 
        "HTTP/1.1 %d OK\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", 
        code, json_view.len
    );
    znet_send(c, zstr_cstr(&h), zstr_len(&h));
    znet_send(c, json, json_view.len);
    zstr_free(&h);
}

// Send 401 Unauthorized (NEVER with WWW-Authenticate to avoid browser popup)
static void send_unauthorized(znet_socket c, zstr_view req) {
    (void)req; // Unused
    
    const char *resp = 
        "HTTP/1.1 401 Unauthorized\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 38\r\n"
        "Connection: close\r\n\r\n"
        "{\"error\":\"Authentication required\"}";
    
    znet_send(c, resp, strlen(resp));
}

// Handle /api/auth/check
static bool handle_auth_check(znet_socket c, zstr_view req) {
    if (!check_basic_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    send_json(c, 200, "{\"status\":\"ok\"}");
    return true;
}

// Handle /api/dashboard/current
static bool handle_current_dashboard(znet_socket c, zstr_view req) {
    if (!check_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    
    time_t now = time(NULL);
    unsigned long uptime = (unsigned long)(now - g_dashboard.start_time);
    unsigned long avg_response = g_dashboard.total_requests > 0 ? 
        (unsigned long)(g_dashboard.response_times_sum / g_dashboard.total_requests) : 0;
    
    zstr json = zstr_init();
    zstr_fmt(&json,
        "{\n"
        "  \"uptime_sec\": %lu,\n"
        "  \"active_clients\": %u,\n"
        "  \"total_requests\": %llu,\n"
        "  \"total_bytes_sent\": %llu,\n"
        "  \"total_mb_sent\": %.2f,\n"
        "  \"avg_response_ms\": %lu,\n"
        "  \"requests_per_sec\": %.2f,\n"
        "  \"timestamp\": %ld,\n"
        "  \"traffic_breakdown\": {\n"
        "    \"html\": %lu,\n"
        "    \"js\": %lu,\n"
        "    \"css\": %lu,\n"
        "    \"img\": %lu,\n"
        "    \"api\": %lu,\n"
        "    \"other\": %lu\n"
        "  }\n"
        "}",
        uptime,
        g_dashboard.active_clients,
        g_dashboard.total_requests,
        g_dashboard.total_bytes_sent,
        (double)g_dashboard.total_bytes_sent / (1024.0 * 1024.0),
        avg_response,
        uptime > 0 ? (double)g_dashboard.total_requests / (double)uptime : 0.0,
        (long)now,
        g_dashboard.req_html,
        g_dashboard.req_js,
        g_dashboard.req_css,
        g_dashboard.req_img,
        g_dashboard.req_api,
        g_dashboard.req_other
    );
    
    send_json(c, 200, zstr_cstr(&json));
    zstr_free(&json);
    return true;
}

// Handle /api/dashboard/history
static bool handle_history_dashboard(znet_socket c, zstr_view req) {
    if (!check_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    
    zstr json = zstr_init();
    zstr_cat(&json, "{\n  \"history\": [\n");
    
    // Get last 30 snapshots
    int count = 0;
    for (int i = 0; i < HISTORY_SIZE && count < 30; i++) {
        int idx = (g_history_index - i + HISTORY_SIZE) % HISTORY_SIZE;
        if (g_history[idx].timestamp == 0) break;
        
        if (count > 0) zstr_cat(&json, ",\n");
        
        zstr temp = zstr_init();
        zstr_fmt(&temp,
            "    {\"timestamp\": %ld, \"clients\": %u, \"rps\": %u, \"avg_ms\": %.3f, \"bytes_kb\": %lu}",
            (long)g_history[idx].timestamp,
            g_history[idx].clients,
            g_history[idx].requests_per_sec,
            (double)g_history[idx].avg_response_us / 1000.0,
            g_history[idx].bytes_sent
        );
        zstr_cat(&json, zstr_cstr(&temp));
        zstr_free(&temp);
        count++;
    }
    
    zstr_cat(&json, "\n  ]\n}");
    
    send_json(c, 200, zstr_cstr(&json));
    zstr_free(&json);
    return true;
}

// Helper to check if a module is enabled in modules.conf
static bool is_module_enabled(const char *mod_name) {
    zstr content = zfile_read_all("modules.conf");
    if (zstr_is_empty(&content)) return false;
    
    char *p = zstr_data(&content);
    char *end = p + zstr_len(&content);
    bool enabled = false;
    
    // We expect lines like: "load modules/mod_name.dll"
    while (p < end) {
        char *line_start = p;
        char *line_end = strchr(p, '\n');
        if (!line_end) line_end = end;
        
        // Check if this line refers to our module
        // We look for "mod_name.dll" or just "mod_name"
        // Let's create a temp view for the line
        size_t line_len = line_end - line_start;
        char *line_copy = (char*)malloc(line_len + 1);
        memcpy(line_copy, line_start, line_len);
        line_copy[line_len] = '\0';
        
        if (strstr(line_copy, mod_name)) {
            // Found the module on this line. Check if it's commented.
            // Scan from start of line
            char *scan = line_copy;
            while (*scan == ' ' || *scan == '\t') scan++;
            
            if (*scan != '#' && *scan != '\0') {
                enabled = true;
                free(line_copy);
                break;
            }
        }
        
        free(line_copy);
        p = line_end + 1;
    }
    
    zstr_free(&content);
    return enabled;
}

// Handle /api/modules/list
static bool handle_modules_list(znet_socket c, zstr_view req) {
    if (!check_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    
    // Scan modules directory
    zdir_iter *it = zdir_open("./modules");
    if (!it) {
        send_json(c, 500, "{\"error\":\"Failed to open modules directory\"}");
        return true;
    }
    
    // Read config once
    zstr config = zfile_read_all("modules.conf");
    
    zstr json = zstr_init();
    zstr_cat(&json, "{\n  \"modules\": [\n");
    
    zdir_entry entry;
    bool first = true;
    
    while (zdir_next(it, &entry)) {
        if (entry.type != ZDIR_FILE) continue;
        
        // Check extension (.dll or .so)
        const char *ext = strrchr(entry.name, '.');
        if (!ext) continue;
        
        if (strcmp(ext, ".dll") != 0 && strcmp(ext, ".so") != 0) continue;
        
        // Get module name (remove extension)
        size_t name_len = ext - entry.name;
        char mod_name[256];
        if (name_len >= sizeof(mod_name)) name_len = sizeof(mod_name) - 1;
        memcpy(mod_name, entry.name, name_len);
        mod_name[name_len] = '\0';
        
        // check status in config
        int status = 0; // 0: not found, 1: disabled, 2: enabled
        
        char *line_start = zstr_data(&config);
        char *config_end = line_start + zstr_len(&config);
        
        while (line_start < config_end) {
             char *line_end = strchr(line_start, '\n');
             if (!line_end) line_end = config_end;
             
             size_t len = line_end - line_start;
             if (len < 1024) {
                 char line_buf[1024];
                 memcpy(line_buf, line_start, len);
                 line_buf[len] = 0;
                 
                 // Check if line contains module name
                 if (strstr(line_buf, mod_name)) {
                     // Check if commented
                     bool commented = false;
                     char *p = line_buf;
                     while(*p == ' ' || *p == '\t') p++;
                     if (*p == '#') commented = true;
                     status = commented ? 1 : 2;
                     break; 
                 }
             }
             line_start = line_end + 1;
        }
        
        // If not in config, skip
        if (status == 0) continue;
        
        if (!first) zstr_cat(&json, ",\n");
        first = false;
        
        bool enabled = (status == 2);
        
        // Load module to get metadata (id and version)
        const char *id = "unknown";
        const char *version = "0.0.0";
        const char *description = "";
        
        char mod_path[512];
        snprintf(mod_path, sizeof(mod_path), "modules/%s", entry.name);
        
#ifdef _WIN32
        HMODULE h = LoadLibrary(mod_path);
        if (h) {
            zmodule_def *mod = (zmodule_def*)GetProcAddress(h, "z_module_entry");
            if (mod) {
                id = mod->id ? mod->id : "unknown";
                version = mod->version ? mod->version : "0.0.0";
                description = mod->description ? mod->description : "";
            }
            FreeLibrary(h);
        }
#else
        void *h = dlopen(mod_path, RTLD_NOW | RTLD_LOCAL);
        if (h) {
            zmodule_def *mod = (zmodule_def*)dlsym(h, "z_module_entry");
            if (mod) {
                id = mod->id ? mod->id : "unknown";
                version = mod->version ? mod->version : "0.0.0";
                description = mod->description ? mod->description : "";
            }
            dlclose(h);
        }
#endif
        
        zstr_fmt(&json, "    {\"name\": \"%s\", \"id\": \"%s\", \"version\": \"%s\", \"description\": \"%s\", \"enabled\": %s}", 
            mod_name, id, version, description, enabled ? "true" : "false");
    }
    
    zdir_close(it);
    zstr_free(&config); // Free config
    zstr_cat(&json, "\n  ]\n}");
    
    send_json(c, 200, zstr_cstr(&json));
    zstr_free(&json);
    return true;
}

// Internal helper to trigger restart
static void trigger_restart(zstr_view req) {
    // Create the trigger file
    FILE *f = fopen(".restart", "w");
    if (f) {
        fprintf(f, "restart");
        fclose(f);
    } 

    // Trigger the server accept loop by making a dummy connection
    char host[256] = {0};
    const char *hstart = strstr(req.data, "Host:");
    if (!hstart) hstart = strstr(req.data, "host:");
    
    if (hstart) {
         hstart += 5;
         while (*hstart == ' ') hstart++;
         const char *hend = strchr(hstart, '\r');
         if (!hend) hend = strchr(hstart, '\n');
         
         if (hend) {
             size_t len = hend - hstart;
             if (len < 255) {
                 memcpy(host, hstart, len);
                 host[len] = '\0';
             }
         }
    }
    
    uint16_t port = 8080; // default
    if (strchr(host, ':')) {
        port = atoi(strchr(host, ':') + 1);
    }
    
    // Connect to wake up
    znet_addr a;
    if (znet_addr_from_str("127.0.0.1", port, &a)) {
        znet_socket s = znet_socket_create(ZNET_IPV4, ZNET_TCP);
        if (s.valid) {
            znet_connect(s, a); 
            znet_close(&s);
        }
    }
}

// Handle /api/modules/toggle
static bool handle_modules_toggle(znet_socket c, zstr_view req) {
    if (!check_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    
    // Scan body for "module" and "enabled"
    // Find body start (after \r\n\r\n)
    const char *body = NULL;
    for (size_t i = 0; i + 4 <= req.len; i++) {
        if (memcmp(req.data + i, "\r\n\r\n", 4) == 0) {
            body = req.data + i + 4;
            break;
        }
    }
    
    if (!body) {
        send_json(c, 400, "{\"error\":\"Missing body\"}");
        return true;
    }
    
    // Simple parsing (avoid complex JSON parser dependency if possible)
    // Look for "module":"name" and "enabled":true/false
    char mod_name[256] = {0};
    bool target_enabled = false;
    
    // Find module name
    const char *p = strstr(body, "\"module\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++; // skip quote
                const char *end = strchr(p, '"');
                if (end) {
                    size_t len = end - p;
                    if (len < sizeof(mod_name)) {
                        memcpy(mod_name, p, len);
                        mod_name[len] = '\0';
                    }
                }
            }
        }
    }
    
    // Find enabled state
    p = strstr(body, "\"enabled\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            while (*p == ' ' || *p == ':' || *p == '"') p++; // skip chars
            if (strncmp(p, "true", 4) == 0) target_enabled = true;
        }
    }
    
    if (mod_name[0] == '\0') {
        send_json(c, 400, "{\"error\":\"Invalid request format\"}");
        return true;
    }
    
    // Modify modules.conf
    zstr content = zfile_read_all("modules.conf");
    zstr new_content = zstr_init();
    
    // We will rebuild the file line by line
    // Limitation: zstr doesn't have split, so we do it manually or line-reader
    // Using zfile_read_all means we have it all in memory. Let's iterate lines.
    
    char *curr = zstr_data(&content);
    char *conf_end = curr + zstr_len(&content);
    bool found = false;
    
    while (curr < conf_end) {
        char *line_start = curr;
        char *line_end = strchr(curr, '\n');
        if (!line_end) line_end = conf_end;
        
        size_t line_len = line_end - line_start;
        // Strip CR if present
        if (line_len > 0 && line_start[line_len-1] == '\r') line_len--;
        
        // Check if this line is for our module
        bool is_target = false;
        
        // Make a stack copy for strstr
        char temp_line[1024];
        size_t copy_len = line_len < 1023 ? line_len : 1023;
        memcpy(temp_line, line_start, copy_len);
        temp_line[copy_len] = '\0';
        
        if (strstr(temp_line, mod_name)) {
             is_target = true;
        }

        if (is_target) {
            found = true;
            // Determine current state (commented or not)
            char *scan = temp_line;
            while (*scan == ' ' || *scan == '\t') scan++;
            bool currently_commented = (*scan == '#');
            
            // Reconstruct the line
            if (target_enabled) {
                // We want it ENABLED.
                if (currently_commented) {
                    // Remove the # and subsequent whitespace
                    scan++; // skip #
                    while (*scan == ' ' || *scan == '\t') scan++;
                    zstr_fmt(&new_content, "%s\n", scan);
                } else {
                    // Already enabled, keep as is
                    zstr_cat_len(&new_content, line_start, line_end - line_start);
                    zstr_cat(&new_content, "\n");
                }
            } else {
                // We want it DISABLED.
                if (!currently_commented) {
                    // Add #
                    zstr_fmt(&new_content, "# %s\n", temp_line);
                } else {
                    // Already disabled, keep as is
                    zstr_cat_len(&new_content, line_start, line_end - line_start);
                    zstr_cat(&new_content, "\n");
                }
            }
        } else {
            // Copy original line
            zstr_cat_len(&new_content, line_start, line_end - line_start);
            zstr_cat(&new_content, "\n");
        }
        
        curr = line_end + 1;
    }
    
    if (!found && target_enabled) {
        // If enabling and not found, append it
        // We assume standard path structure
        zstr_fmt(&new_content, "load modules/%s.dll\n", mod_name);
    }
    
    // Write back
    // Backup first? Maybe.
    zfile_save_atomic("modules.conf", zstr_data(&new_content), zstr_len(&new_content));
    
    zstr_free(&content);
    zstr_free(&new_content);
    
    send_json(c, 200, "{\"status\":\"ok\", \"message\":\"Module toggled. Server restarting...\"}");
    trigger_restart(req);
    return true;
}

// Handle /api/dashboard/reset
static bool handle_reset_dashboard(znet_socket c, zstr_view req) {
    if (!check_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    
    // Reset stats
    g_dashboard.total_requests = 0;
    g_dashboard.total_bytes_sent = 0;
    g_dashboard.response_times_sum = 0;
    g_dashboard.last_reset = time(NULL);
    memset(g_history, 0, sizeof(g_history));
    g_history_index = 0;
    
    send_json(c, 200, "{\"status\":\"reset_complete\"}");
    return true;
}

// Handle /api/modules/delete
static bool handle_modules_delete(znet_socket c, zstr_view req) {
    if (!check_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    
    // Parse body for "module"
    const char *body = NULL;
    for (size_t i = 0; i + 4 <= req.len; i++) {
        if (memcmp(req.data + i, "\r\n\r\n", 4) == 0) {
            body = req.data + i + 4;
            break;
        }
    }
    
    if (!body) {
        send_json(c, 400, "{\"error\":\"Missing body\"}");
        return true;
    }
    
    char mod_name[256] = {0};
    const char *p = strstr(body, "\"module\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++; 
                const char *end = strchr(p, '"');
                if (end) {
                    size_t len = end - p;
                    if (len < sizeof(mod_name)) {
                        memcpy(mod_name, p, len);
                        mod_name[len] = '\0';
                    }
                }
            }
        }
    }
    
    if (mod_name[0] == '\0') {
         send_json(c, 400, "{\"error\":\"Invalid module name\"}");
         return true;
    }
    
    // Safety checks
    if (strstr(mod_name, "..") || strchr(mod_name, '/') || strchr(mod_name, '\\')) {
         send_json(c, 400, "{\"error\":\"Invalid module name security\"}");
         return true;
    }
    
    if (strcmp(mod_name, "mod_dashboard") == 0) {
         send_json(c, 400, "{\"error\":\"Cannot delete the active dashboard module\"}");
         return true;
    }

    // 1. Remove from modules.conf
    zstr content = zfile_read_all("modules.conf");
    zstr new_content = zstr_init();
    
    char *curr = zstr_data(&content);
    char *conf_end = curr + zstr_len(&content);
    
    while (curr < conf_end) {
        char *line_start = curr;
        char *line_end = strchr(curr, '\n');
        if (!line_end) line_end = conf_end;
        
        size_t line_len = line_end - line_start;
        char temp_line[1024];
        size_t copy_len = line_len < 1023 ? line_len : 1023;
        memcpy(temp_line, line_start, copy_len);
        temp_line[copy_len] = '\0';
        
        // If this line contains the module AND "load modules/", skip it
        if (strstr(temp_line, mod_name) && strstr(temp_line, "load modules/")) {
            // Skip this line (effective delete)
        } else {
            zstr_cat_len(&new_content, line_start, line_end - line_start);
            zstr_cat(&new_content, "\n");
        }
        curr = line_end + 1;
    }
    
    zfile_save_atomic("modules.conf", zstr_data(&new_content), zstr_len(&new_content));
    zstr_free(&content);
    zstr_free(&new_content);
    
    // 2. Delete files
    char path[512];
    
    // Delete .c
    snprintf(path, sizeof(path), "modules/%s.c", mod_name);
    remove(path);
    
    // Delete .dll
    snprintf(path, sizeof(path), "modules/%s.dll", mod_name);
    int dll_res = remove(path);
    
    // Delete .so
    snprintf(path, sizeof(path), "modules/%s.so", mod_name);
    remove(path);
    
    if (dll_res != 0) {
        // On Windows if it fails, it might be locked. We can't do much.
    }

    send_json(c, 200, "{\"status\":\"ok\", \"message\":\"Module deleted. Server restarting...\"}");
    trigger_restart(req);
    return true;
}

// Handle /api/modules/install
static bool handle_modules_install(znet_socket c, zstr_view req) {
    if (!check_auth(req)) {
        send_unauthorized(c, req);
        return true;
    }
    
    // 0. Find body start in headers
    const char *body_ptr = NULL;
    for (size_t i = 0; i + 4 <= req.len; i++) {
        if (memcmp(req.data + i, "\r\n\r\n", 4) == 0) {
            body_ptr = req.data + i + 4;
            break;
        }
    }
    
    if (!body_ptr) {
        send_json(c, 400, "{\"error\":\"Invalid HTTP request\"}");
        return true;
    }

    // 1. Parse Content-Length from headers
    unsigned long long content_length = 0;
    const char *scan = req.data;
    while (scan < body_ptr) {
        if (strncmp(scan, "Content-Length:", 15) == 0 || strncmp(scan, "content-length:", 15) == 0) {
             content_length = strtoull(scan + 15, NULL, 10);
             break;
        }
        const char *next = memchr(scan, '\n', body_ptr - scan);
        if (!next) break;
        scan = next + 1;
    }
    
    if (content_length == 0) {
        send_json(c, 400, "{\"error\":\"Missing or invalid Content-Length\"}");
        return true;
    }
    
    // 2. Read full body from socket
    size_t body_in_buffer = req.len - (body_ptr - req.data);
    
    // Calculate how much more data we need to read
    size_t total_needed = content_length;
    char *full_body = malloc(total_needed + 1);
    if (!full_body) {
        send_json(c, 500, "{\"error\":\"Out of memory\"}");
        return true;
    }
    
    // Copy what we already have
    if (body_in_buffer > total_needed) body_in_buffer = total_needed;
    memcpy(full_body, body_ptr, body_in_buffer);
    size_t total_read = body_in_buffer;
    
    // Read remaining
    while (total_read < total_needed) {
        char buf[4096];
        z_ssize_t n = znet_recv(c, buf, 
            (total_needed - total_read) > 4096 ? 4096 : (total_needed - total_read));
        if (n <= 0) break;
        memcpy(full_body + total_read, buf, n);
        total_read += n;
    }
    full_body[total_read] = '\0';
    
    // 3. Parse JSON body for filename and code
    char filename[256] = {0};
    const char *p = strstr(full_body, "\"filename\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p = strchr(p, '"');
            if (p) {
                p++;
                const char *end = strchr(p, '"');
                if (end && (end - p < sizeof(filename))) {
                    memcpy(filename, p, end - p);
                    filename[end - p] = '\0';
                }
            }
        }
    }
    
    if (filename[0] == '\0' || strstr(filename, "..") || strchr(filename, '/') || strchr(filename, '\\')) {
        char err[256];
        snprintf(err, sizeof(err), "{\"error\":\"Invalid filename: '%s'\"}", filename);
        send_json(c, 400, err);
        free(full_body);
        return true;
    }
    
    // Extract code
    const char *p_code = strstr(full_body, "\"code\"");
    if (!p_code) {
        send_json(c, 400, "{\"error\":\"Missing code field\"}");
        free(full_body);
        return true;
    }
    
    p_code = strchr(p_code, ':');
    if (p_code) {
        while (*p_code == ' ' || *p_code == ':') p_code++;
        if (*p_code == '"') p_code++;
    }
    
    // Unescape JSON string
    zstr code_content = zstr_init();
    const char *curr = p_code;
    while (curr && *curr) {
        if (*curr == '\\') {
            curr++;
            if (*curr == 'n') zstr_cat(&code_content, "\n");
            else if (*curr == 'r') zstr_cat(&code_content, "\r");
            else if (*curr == 't') zstr_cat(&code_content, "\t");
            else if (*curr == '"') zstr_cat(&code_content, "\"");
            else if (*curr == '\\') zstr_cat(&code_content, "\\");
            else zstr_cat_len(&code_content, curr, 1);
        } else if (*curr == '"') {
            break;
        } else {
            zstr_cat_len(&code_content, curr, 1);
        }
        curr++;
    }
    
    free(full_body);
    
    // 4. Save to file
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "modules/%s", filename);
    FILE *f = fopen(filepath, "wb");
    if (!f) {
        send_json(c, 500, "{\"error\":\"Failed to open file for writing\"}");
        zstr_free(&code_content);
        return true;
    }
    
    fwrite(zstr_data(&code_content), 1, zstr_len(&code_content), f);
    fclose(f);
    zstr_free(&code_content);

    // 5. Compile
    char mod_name[256];
    char *dot = strrchr(filename, '.');
    size_t name_len = dot ? (size_t)(dot - filename) : strlen(filename);
    if (name_len >= sizeof(mod_name)) name_len = sizeof(mod_name) - 1;
    memcpy(mod_name, filename, name_len);
    mod_name[name_len] = '\0';

#ifdef _WIN32
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), 
        "gcc -shared -o modules/%s.dll modules/%s -O2 -std=c11 -lws2_32 "
        "-DZNET_IMPLEMENTATION -DZTHREAD_IMPLEMENTATION -DZSTR_IMPLEMENTATION "
        "-DZFILE_IMPLEMENTATION -DZERROR_IMPLEMENTATION",
        mod_name, filename);
    int res = system(cmd);
#else
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), 
        "gcc -shared -fPIC -o modules/%s.so modules/%s -O2 -std=c11 "
        "-DZNET_IMPLEMENTATION -DZTHREAD_IMPLEMENTATION -DZSTR_IMPLEMENTATION "
        "-DZFILE_IMPLEMENTATION -DZERROR_IMPLEMENTATION",
        mod_name, filename);
    int res = system(cmd);
#endif

    if (res != 0) {
        send_json(c, 500, "{\"error\":\"Compilation failed\"}");
        return true;
    }

    // 6. Add to modules.conf
    zstr config = zfile_read_all("modules.conf");
    if (zstr_find(&config, mod_name) == -1) {
#ifdef _WIN32
        zstr_cat(&config, "load modules/");
        zstr_cat(&config, mod_name);
        zstr_cat(&config, ".dll\n");
#else
        zstr_cat(&config, "load modules/");
        zstr_cat(&config, mod_name);
        zstr_cat(&config, ".so\n");
#endif
        zfile_save_atomic("modules.conf", zstr_data(&config), zstr_len(&config));
    }
    zstr_free(&config);

    send_json(c, 200, "{\"status\":\"ok\", \"message\":\"Installed and compiled. Server restarting...\"}");
    trigger_restart(req);
    return true;
}


// Serve static assets from modules/mod_dashboard/
static bool handle_static_assets(znet_socket c, zstr_view path) {
    // Safety check for directory traversal
    zstr path_str = zstr_from_len(path.data, path.len);
    if (strstr(zstr_cstr(&path_str), "..")) {
        zstr_free(&path_str);
        return false;
    }
    zstr_free(&path_str);
    
    // Construct local file path
    zstr local_path = zstr_init();
    zstr_cat(&local_path, "modules/mod_dashboard");
    
    // path starts with "/dashboard" (length 10)
    // If it's exactly "/dashboard", serve /dashboard.html ? No, browser needs redirect or relative toroot.
    // If we are here, caller checked prefix.
    
    if (path.len == 10) { // "/dashboard"
         // Redirect to /dashboard/dashboard.html
         const char *resp = "HTTP/1.1 302 Found\r\nLocation: /dashboard/dashboard.html\r\nConnection: close\r\n\r\n";
         znet_send(c, resp, strlen(resp));
         zstr_free(&local_path);
         return true;
    } else if (path.len == 11 && path.data[10] == '/') { // "/dashboard/"
         zstr_cat(&local_path, "/dashboard.html");
    } else {
         // Append everything after "/dashboard"
         zstr_cat_len(&local_path, path.data + 10, path.len - 10);
    }
    
    // Read file
    zstr content = zfile_read_all(zstr_cstr(&local_path));
    if (zstr_is_empty(&content)) {
        zstr_free(&local_path);
        // Let main server 404 (return false)
        return false;
    }
    
    // Determine content type
    const char *mime = "text/plain";
    if (zstr_ends_with(&local_path, ".html")) mime = "text/html";
    else if (zstr_ends_with(&local_path, ".css")) mime = "text/css";
    else if (zstr_ends_with(&local_path, ".js")) mime = "application/javascript";
    else if (zstr_ends_with(&local_path, ".png")) mime = "image/png";
    else if (zstr_ends_with(&local_path, ".jpg")) mime = "image/jpeg";
    else if (zstr_ends_with(&local_path, ".svg")) mime = "image/svg+xml";
    else if (zstr_ends_with(&local_path, ".ico")) mime = "image/x-icon";
    else if (zstr_ends_with(&local_path, ".json")) mime = "application/json";

    // Inject Token into dashboard.js
    if (zstr_ends_with(&local_path, "dashboard.js")) {
        // Simple manual replacement of __SESSION_TOKEN__
        const char *placeholder = "__SESSION_TOKEN__";
        char *pos = strstr(zstr_data(&content), placeholder);
        if (pos) {
            zstr new_content = zstr_init();
            // Copy before
            zstr_cat_len(&new_content, zstr_data(&content), pos - zstr_data(&content));
            // Copy token
            zstr_cat(&new_content, g_session_token);
            // Copy after
            zstr_cat(&new_content, pos + strlen(placeholder));
            
            zstr_free(&content);
            content = new_content; // Move ownership
        }
    }

    // Send response
    zstr header = zstr_init();
    zstr_fmt(&header, 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n", 
        mime, zstr_len(&content)
    );
    
    // For binary safety with images, verify znet_send usage logic
    znet_send(c, zstr_cstr(&header), zstr_len(&header));
    znet_send(c, zstr_data(&content), zstr_len(&content));
    
    zstr_free(&header);
    zstr_free(&content);
    zstr_free(&local_path);
    return true;
}

// Main handler
bool dashboard_handler(znet_socket c, zstr_view m, zstr_view p, zstr_view req, zstr_view ip) 
{
    (void)ip;
    init_dashboard();
    
    // Capture start time for this request
    unsigned long long start_time = get_time_us();
    bool handled = false;
    
    // Handle stats API endpoints
    if (zstr_view_eq(p, "/api/dashboard/current")) {
        handled = handle_current_dashboard(c, req);
    }
    else if (zstr_view_eq(p, "/api/auth/check")) {
        handled = handle_auth_check(c, req);
    }
    else if (zstr_view_eq(p, "/api/dashboard/history")) {
        handled = handle_history_dashboard(c, req);
    }
    else if (zstr_view_eq(p, "/api/dashboard/reset") && zstr_view_eq(m, "POST")) {
        handled = handle_reset_dashboard(c, req);
    }
    else if (zstr_view_eq(p, "/api/modules/list")) {
        handled = handle_modules_list(c, req);
    }
    else if (zstr_view_eq(p, "/api/modules/toggle") && zstr_view_eq(m, "POST")) {
        handled = handle_modules_toggle(c, req);
    }
    else if (zstr_view_eq(p, "/api/modules/delete") && zstr_view_eq(m, "POST")) {
        handled = handle_modules_delete(c, req);
    }
    else if (zstr_view_eq(p, "/api/modules/install") && zstr_view_eq(m, "POST")) {
        handled = handle_modules_install(c, req);
    }
    else if (zstr_view_starts_with(p, "/dashboard")) {
        handled = handle_static_assets(c, p);
    }
    // Protect ONLY dashboard.html - REMOVED to avoid browser auth dialog
    // The API is already protected, so we can let the HTML load
    // and let the JS handle the authentication with the API

    
    // Track this request if it was handled or is any other request
    if (handled || !zstr_view_starts_with(p, "/api/dashboard") && !zstr_view_starts_with(p, "/api/modules")) {
        unsigned long long elapsed = get_time_us() - start_time;
        // Estimate bytes sent (could be improved by tracking actual response size)
        unsigned long bytes_estimate = 512;
        
        // Adjust estimate based on path
        if (zstr_view_ends_with(p, ".html")) bytes_estimate = 2048;
        else if (zstr_view_ends_with(p, ".js")) bytes_estimate = 4096;
        else if (zstr_view_ends_with(p, ".css")) bytes_estimate = 2048;
        else if (zstr_view_starts_with(p, "/api/")) bytes_estimate = 256;
        
        track_request(bytes_estimate, elapsed, p, ip);
    }
    
    return handled;
}

zmodule_def z_module_entry = 
{ 
    .name = "mod_dashboard",
    .id = "core-001",
    .version = "1.0.0",
    .description = "Web control panel with real-time statistics and module management.",
    .handler = dashboard_handler 
};
