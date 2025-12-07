#include "hook_global_state.h"
#include <stdio.h>

FdTable fd_table_storage;
int unix_socket = -1;

int init_connection_storage()
{
    /*
     * fdt_init_from_rlimit can be used too
     * uses global max socket limit. not needed for our example :)
     */

    if (fdt_init(&fd_table_storage, MAX_SOCKETS) != 0) {
        return -1;
    }

    return 0;
}