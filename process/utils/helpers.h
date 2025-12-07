#ifndef PROCESS_HELPERS_H
#define PROCESS_HELPERS_H

#include "envs.h"
#include <stdio.h>

typedef void (*callback_t)(void *);

int set_timeout(unsigned int seconds, callback_t cb, void *arg);

ssize_t read_n(int fd, void *buf, size_t n);

void debug_print(
    FILE* stream,
    const char* __restrict format, ...);

#endif //PROCESS_HELPERS_H