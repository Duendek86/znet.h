
#include <time.h>
#include "../zmodule.h"
#include "../zthread.h"

static zmutex_t lock; 

__attribute__((constructor))
static void logger_init(void) 
{
    zmutex_init(&lock);
}

bool logger_handler(znet_socket c, zstr_view m, zstr_view p, zstr_view req, zstr_view ip) 
{
    (void)c; 
    
    time_t now = time(NULL); 
    char tbuf[64]; 
    strftime(tbuf,64,"%H:%M:%S", localtime(&now));
    
    zstr_view ua = ZSV("-");
    const char *u = strstr(req.data, "User-Agent: ");
    if(u) 
    { 
        u += 12; 
        const char *eol = strchr(u, '\r'); 
        if(eol) ua = zstr_sub(zstr_view_from(u), 0, eol - u); 
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
