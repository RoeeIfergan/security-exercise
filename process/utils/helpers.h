#ifndef PROCESS_HELPERS_H
#define PROCESS_HELPERS_H

#include <stdio.h>

#define DEBUG 0

typedef void (*callback_t)(void *);

int set_timeout(unsigned int seconds, callback_t cb, void *arg);

void debug_print(
    FILE* stream,
    const char* __restrict format, ...);

#endif //PROCESS_HELPERS_H