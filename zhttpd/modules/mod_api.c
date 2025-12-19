
#include "../zmodule.h"

static void send_json(znet_socket c, int code, zstr_view json) 
{
    zstr h = zstr_init();
    zstr_fmt(&h, "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", code, json.len);
    znet_send(c, zstr_cstr(&h), zstr_len(&h));
    znet_send(c, json.data, json.len);
    zstr_free(&h);
}

bool api_handler(znet_socket c, zstr_view m, zstr_view path, zstr_view req, zstr_view ip) 
{
    (void)req; (void)ip;
    if (zstr_view_eq(path, "/api/status")) 
    {
        send_json(c, 200, ZSV("{\"status\": \"running\", \"engine\": \"zhttpd-v4\"}"));
        return true; 
    }
    if (zstr_view_eq(path, "/api/email") && 
        zstr_view_eq(m, "POST")) 
    {
        send_json(c, 200, ZSV("{\"email_sent\": true}"));
        return true;
    }
    return false; 
}

zmodule_def z_module_entry = 
{ 
    .name = "API", 
    .handler = api_handler 
};
