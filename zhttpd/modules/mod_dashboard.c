#include "../zmodule.h"
#include "../zfile.h"
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define ATOMIC_INCREMENT(x) InterlockedIncrement((LONG*)&(x))
#define ATOMIC_ADD(x, val) InterlockedAdd((LONG*)&(x), (LONG)(val))
#else
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

// Initialize dashboard stats on first load
static void init_dashboard(void) {
    static int initialized = 0;
    if (!initialized) {
        g_dashboard.start_time = time(NULL);
        g_dashboard.last_reset = g_dashboard.start_time;
        g_last_snapshot = g_dashboard.start_time;
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

// Check authentication - search within bounded buffer
static bool check_auth(zstr_view req) {
    // Just search for the Base64 encoded credentials anywhere in the request
    // This is simpler and more reliable than trying to parse headers
    const char *expected_token = "YWRtaW46c3RhdHMxMjM=";
    size_t token_len = 16;
    
    // Naive string search within the buffer
    for (size_t i = 0; i + token_len <= req.len; i++) {
        if (memcmp(req.data + i, expected_token, token_len) == 0) {
            return true;
        }
    }
    
    return false;
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

// Send 401 Unauthorized
static void send_unauthorized(znet_socket c, zstr_view req) {
    // Check if this is an AJAX request (has X-Requested-With header)
    bool is_ajax = false;
    const char *ajax_marker = "X-Requested-With:";
    for (size_t i = 0; i + 17 <= req.len; i++) {
        if (memcmp(req.data + i, ajax_marker, 17) == 0) {
            is_ajax = true;
            break;
        }
    }
    
    const char *resp;
    size_t resp_len;
    
    if (is_ajax) {
        // For AJAX: don't send WWW-Authenticate to avoid browser dialog
        resp = 
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 38\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"Authentication required\"}";
        resp_len = 137;
    } else {
        // For browser navigation: include WWW-Authenticate
        resp = 
            "HTTP/1.1 401 Unauthorized\r\n"
            "WWW-Authenticate: Basic realm=\"ZHTTPD Dashboard\"\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 38\r\n"
            "Connection: close\r\n\r\n"
            "{\"error\":\"Authentication required\"}";
        resp_len = 181;
    }
    
    znet_send(c, resp, resp_len);
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
        
        if (!first) zstr_cat(&json, ",\n");
        first = false;
        
        bool enabled = is_module_enabled(mod_name);
        
        zstr_fmt(&json, "    {\"name\": \"%s\", \"enabled\": %s}", 
            mod_name, enabled ? "true" : "false");
    }
    
    zdir_close(it);
    zstr_cat(&json, "\n  ]\n}");
    
    send_json(c, 200, zstr_cstr(&json));
    zstr_free(&json);
    return true;
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
    
    send_json(c, 200, "{\"status\":\"ok\"}");
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
    .name = "Dashboard", 
    .handler = dashboard_handler 
};
