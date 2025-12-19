
#include <time.h>
#include "../zmodule.h"
#include "../zthread.h"
#define LIMIT 5

unsigned long hash_v(zstr_view s) 
{
    unsigned long h = 5381;
    for(size_t i = 0; i < s.len; i++) 
    {
        h = ((h << 5) + h) + s.data[i];
    }
    return h % 128;
}

static struct 
{ 
    char ip[64]; 
    time_t t; 
    int c; 
} track[128];

static zmutex_t lock; 
static bool init = 0;

bool ratelimit_handler(znet_socket c, zstr_view m, zstr_view p, zstr_view r, zstr_view ip) 
{
    (void)m; 
    (void)p; 
    (void)r;
    if(!init)
    {
        zmutex_init(&lock);
        init = 1;
    }
    
    bool block = false;
    time_t now = time(NULL);
    int idx = hash_v(ip);
    
    zmutex_lock(&lock);
    if(0 != strncmp(track[idx].ip, ip.data, ip.len)) 
    {
        snprintf(track[idx].ip, 64, "%.*s", (int)ip.len, ip.data);
        track[idx].t = now; 
        track[idx].c = 0;
    }
    if (now != track[idx].t) 
    { 
        track[idx].t = now; 
        track[idx].c = 0; 
    }
    if (++track[idx].c > LIMIT) 
    {
        block = true;
    }
    zmutex_unlock(&lock);

    if (block) 
    {
        const char *resp = "HTTP/1.1 429 Too Many\r\n\r\nBlocked";
        znet_send(c, resp, strlen(resp));
        return true;
    }
    return false;
}

zmodule_def z_module_entry = 
{ 
    .name = "RateLimit", 
    .handler = ratelimit_handler 
};
