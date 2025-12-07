
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include "helpers.h"
#include <errno.h>

struct timer_data {
    unsigned int seconds;
    callback_t cb;
    void *arg;
};

static void *timer_thread(void *ptr) {
    struct timer_data *data = ptr;

    sleep(data->seconds);
    data->cb(data->arg);

    free(data);
    return NULL;
}

int set_timeout(unsigned int seconds, callback_t cb, void *arg) {
    pthread_t tid;
    struct timer_data *data = malloc(sizeof(*data));
    if (!data) return -1;

    data->seconds = seconds;
    data->cb = cb;
    data->arg = arg;

    if (pthread_create(&tid, NULL, timer_thread, data) != 0) {
        free(data);
        return -1;
    }

    pthread_detach(tid);

    return 0;
}

ssize_t read_n(int fd, void *buf, size_t n) {
    size_t total = 0;
    char *p = buf;

    while (total < n) {
        ssize_t r = recv(fd, p + total, n - total, 0);
        if (r == 0) {
            // Peer closed the connection
            break;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;   // interrupted by signal, retry
            }
            return -1;  // error
        }
        total += r;
    }

    return (ssize_t)total;  // may be < n if EOF
}

void debug_print(
    FILE* stream,
    const char* __restrict format, ...)
{
    if (DEBUG == 0) return;

    va_list ap;
    va_start(ap, format);

    vfprintf(stream, format, ap);

    va_end(ap);
}
