#ifndef PROCESS_HOOK_GLOBAL_STATE_H
#define PROCESS_HOOK_GLOBAL_STATE_H

#include "../connection_storage.h"

#define MAX_SOCKETS 1000

extern FdTable fd_table_storage;


int init_connection_storage();

extern int unix_socket;

#endif //PROCESS_HOOK_GLOBAL_STATE_H