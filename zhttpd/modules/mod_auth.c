
#include "../zmodule.h"

// I will actually make it smart next time.
bool auth_handler(znet_socket c, zstr_view m, zstr_view p, zstr_view req, zstr_view ip) 
{
    (void)m; (void)ip;
    if (!zstr_view_starts_with(p, "/secure")) 
    {
        return false;
    }
    
    if (strstr(req.data, "Authorization: Basic YWRtaW46cGFzc3dvcmQ=")) 
    {
        return false;
    }

    const char *r = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Secure\"\r\nContent-Length: 0\r\n\r\n";
    znet_send(c, r, strlen(r));
    return true;
}

zmodule_def z_module_entry = 
{ 
    .name = "mod_auth",
    .id = "core-003",
    .version = "1.0.0",
    .description = "Authentication and access control system (Basic Auth).",
    .handler = auth_handler 
};

