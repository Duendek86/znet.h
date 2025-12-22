
#include <time.h>
#include <sys/stat.h>
#include "../zmodule.h"
#include "../zthread.h"
#include "../zfile.h"

#define MAX_LOG_SIZE (1024 * 1024)  // 1MB per file
#define MAX_LOG_FILES 5              // Keep last 5 files

static zmutex_t lock; 

__attribute__((constructor))
static void logger_init(void) 
{
    zmutex_init(&lock);
}

static void rotate_logs(void)
{
    // Delete oldest log if it exists
    char oldest[64];
    snprintf(oldest, sizeof(oldest), "access.%d.log", MAX_LOG_FILES - 1);
    remove(oldest);
    
    // Rotate existing logs
    for (int i = MAX_LOG_FILES - 2; i >= 0; i--) {
        char old_name[64], new_name[64];
        
        if (i == 0) {
            snprintf(old_name, sizeof(old_name), "access.log");
        } else {
            snprintf(old_name, sizeof(old_name), "access.%d.log", i);
        }
        snprintf(new_name, sizeof(new_name), "access.%d.log", i + 1);
        
        rename(old_name, new_name);
    }
}

static long get_file_size(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return 0;
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
    
    // Check if rotation is needed
    if (get_file_size("access.log") >= MAX_LOG_SIZE) {
        rotate_logs();
    }
    
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
    .name = "mod_logger",
    .id = "core-004",
    .version = "1.0.0",
    .description = "Advanced request and server error logging.",
    .handler = logger_handler 
};
