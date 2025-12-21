
#include "../zmodule.h"
#include "../zfile.h"

bool vhost_handler(znet_socket c, zstr_view m, zstr_view p, zstr_view req, zstr_view ip) 
{
    (void)m; 
    (void)ip;
    const char *h_ptr = strstr(req.data, "Host: ");
    if (!h_ptr) 
    {
        return false;
    }
    
    zstr_view host = zstr_view_from(h_ptr + 6);
    const char *eol = strchr(host.data, '\r');
    if (!eol) 
    {
        return false;
    }
    host = zstr_sub(host, 0, eol - host.data);
    
    zstr path = zstr_init();
    zstr_fmt(&path, "sites/%.*s%.*s", ZSV_ARG(host), ZSV_ARG(p));
    if (zstr_ends_with(&path, "/")) 
    {
        zstr_cat(&path, "index.html");
    }

    FILE *f = fopen(zstr_cstr(&path), "rb");
    zstr_free(&path);
    
    if (f) 
    {
        fseek(f, 0, SEEK_END); 
        long sz = ftell(f); 
        fseek(f, 0, SEEK_SET);
        zstr hd = zstr_init();
        zstr_fmt(&hd, "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", sz);
        znet_send(c, zstr_cstr(&hd), zstr_len(&hd));
        zstr_free(&hd);
        char b[4096]; size_t n;

        while((n = fread(b, 1, 4096, f)) > 0) 
        {
            znet_send(c, b, n);
        }
        fclose(f);
        return true;
    }
    return false;
}

zmodule_def z_module_entry = 
{ 
    .name = "mod_vhost",
    .id = "core-008",
    .version = "1.0.0",
    .description = "Multiple domain and virtual host management on a single instance.",
    .handler = vhost_handler 
};
