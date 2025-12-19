
#include <time.h>
#include "../zmodule.h"
#include "../zthread.h"

static zmutex_t lock; 
static bool init = 0;

bool logger_handler(znet_socket c, zstr_view m, zstr_view p, zstr_view req, zstr_view ip) 
{
    (void)c; 
    if(!init)
    {
        zmutex_init(&lock);
        init = 1;
    }
    
    time_t now = time(NULL); 
    char tbuf[64]; 
    strftime(tbuf,64,"%H:%M:%S", localtime(&now));
    
    zstr_view ua = ZSV("-");
    const char *u = strstr(req.data, "User-Agent: ");
    if(u) 
    { 
        u += 12; 
        const char *eol = strchr(u, '\r'); 
        if(eol) 
        {
            ua = zstr_sub(zstr_view_from(u), 0, eol - u); 
        }
    }

    zmutex_lock(&lock);
    FILE *f = fopen("access.log", "a");
    if(f) 
    {
        fprintf(f, "%.*s - [%s] \"%.*s %.*s\" \"%.*s\"\n", 
            ZSV_ARG(ip), tbuf, ZSV_ARG(m), ZSV_ARG(p), ZSV_ARG(ua));
        fclose(f);
    }
    zmutex_unlock(&lock);
    return false;
}

zmodule_def z_module_entry = 
{ 
    .name = "Logger", 
    .handler = logger_handler 
};
