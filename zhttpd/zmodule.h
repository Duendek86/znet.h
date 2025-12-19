
// zmodule.h ig.

#ifndef ZMODULE_H
#define ZMODULE_H

#include <stdbool.h>
#include "znet.h"
#include "zstr.h"

typedef bool (*zmodule_handler)(
    znet_socket client, 
    zstr_view method, 
    zstr_view path, 
    zstr_view full_req,
    zstr_view client_ip
);

typedef struct 
{
    const char *name;
    zmodule_handler handler;
} zmodule_def;

#define Z_MODULE_ENTRY_SYM "z_module_entry"

#endif
