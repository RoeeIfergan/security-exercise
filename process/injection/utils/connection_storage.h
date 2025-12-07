#ifndef PROCESS_CONNECTION_STORAGE_H
#define PROCESS_CONNECTION_STORAGE_H

#include <stddef.h>

#include "../../connection_management.h"

typedef char FD_Data[HOME_IDENTIFIER_LEN];

typedef struct {
    FD_Data data;
} FdMeta;

typedef struct {
    FdMeta        *meta;     // array of size max_fds
    unsigned long *used;     // bitset of size ceil(max_fds / (8*sizeof(unsigned long)))
    size_t         max_fds;  // maximum fd index + 1
} FdTable;

/* Initialize using an explicit max_fds */
int  fdt_init(FdTable *t, size_t max_fds);

/* Initialize using RLIMIT_NOFILE (soft limit) */
int  fdt_init_from_rlimit(FdTable *t);

void fdt_free(FdTable *t);

int  fdt_set(FdTable *t, int fd, const FD_Data);

FdMeta *fdt_get(FdTable *t, int fd);

void fdt_remove(FdTable *t, int fd);

int  fdt_pop(FdTable *t, int fd, FD_Data);

#endif //PROCESS_CONNECTION_STORAGE_H