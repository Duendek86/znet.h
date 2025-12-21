
#include "../zmodule.h"
#include "../zthread.h"
#define MAX_KEYS 100

typedef struct { zstr key; zstr val; bool active; } kv_t;

static kv_t db[MAX_KEYS];
static zmutex_t lock;

__attribute__((constructor))
static void memdb_init(void) 
{
    zmutex_init(&lock);
}

static void send_msg(znet_socket c, int code, zstr_view m) 
{
    zstr h = zstr_init();
    zstr_fmt(&h, "HTTP/1.1 %d OK\r\nContent-Length: %zu\r\n\r\n", code, m.len);
    znet_send(c, zstr_cstr(&h), zstr_len(&h));
    znet_send(c, m.data, m.len);
    zstr_free(&h);
}

bool memdb_handler(znet_socket c, zstr_view m, zstr_view path, zstr_view req, zstr_view ip) 
{
    (void)req; (void)ip;
    
    if (!zstr_view_starts_with(path, "/db")) 
    {
        return false;
    }

    zstr_split_iter it = zstr_split_init(path, "/");
    zstr_view part, key = {0}, val = {0};
    zstr_split_next(&it, &part);
    zstr_split_next(&it, &part);
    if (zstr_split_next(&it, &key)) 
    {
        zstr_split_next(&it, &val);
    }

    if (0 == key.len) 
    {
        if (zstr_view_eq(m, "GET")) 
        {
            zstr buf = zstr_from("MEMDB:\n");
            zmutex_lock(&lock);
            for(int i = 0; i < MAX_KEYS; i++) 
            {
                if(db[i].active) 
                {
                    zstr_fmt(&buf, "%s = %s\n", zstr_cstr(&db[i].key), zstr_cstr(&db[i].val));
                }
            }
            zmutex_unlock(&lock);
            send_msg(c, 200, zstr_as_view(&buf));
            zstr_free(&buf);
            return true;
        }
        send_msg(c, 400, ZSV("Bad Request"));
        return true; 
    }

    if (zstr_view_eq(m, "PUT") || zstr_view_eq(m, "POST")) 
    {
        zmutex_lock(&lock);
        for(int i = 0; i < MAX_KEYS; i++) 
        {
            if (!db[i].active || zstr_view_eq_view(zstr_as_view(&db[i].key), key)) {

                if(db[i].active) 
                { 
                    zstr_free(&db[i].key); 
                    zstr_free(&db[i].val); 
                }
                db[i].key = zstr_from_view(key);
                db[i].val = zstr_from_view(val);
                db[i].active = true;
                break;
            }
        }
        zmutex_unlock(&lock);
        send_msg(c, 201, ZSV("Saved")); 
        return true;
    }

    if (zstr_view_eq(m, "GET")) 
    {
        zmutex_lock(&lock);
        for(int i = 0; i < MAX_KEYS; i++) 
        {
            if(db[i].active && zstr_view_eq_view(zstr_as_view(&db[i].key), key)) 
            { 
                 send_msg(c, 200, zstr_as_view(&db[i].val));
                 zmutex_unlock(&lock); 
                 return true;
            }
        }
        zmutex_unlock(&lock);
        send_msg(c, 404, ZSV("Not Found")); 
        return true;
    }
    return false;
}

zmodule_def z_module_entry = 
{ 
    .name = "mod_memdb",
    .id = "core-005",
    .version = "1.0.0",
    .description = "Lightweight in-memory database for fast temporary storage.",
    .handler = memdb_handler 
};
