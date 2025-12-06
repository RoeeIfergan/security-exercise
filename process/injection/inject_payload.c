
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <sys/mman.h>

#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>

#include "../utils/unix_socket.h"
#include "./utils/got_injection.h"
#include "../utils/helpers.h"

static int (*real_printf)(const char *fmt, ...) = NULL;

//TODO: Supress all logs in this file so server doesn't know it was injected. use the debug_print()

/* -------- our replacement printf -------- */

static int my_printf(const char *fmt, ...)
{
    if (!real_printf) {
        // Fallback: resolve original printf if GOT hook didn't set it
        real_printf = dlsym(RTLD_NEXT, "printf");
        if (!real_printf) {
            // If this fails, avoid recursion and just bail
            return -1;
        }
    }

    va_list ap;
    va_start(ap, fmt);
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    real_printf("[HOOKED] %s", buf);

    return n;
}

/* -------- constructor -------- */
void my_callback(void *arg) {
    fprintf(stderr, "connection to unix-socket..\n");
    int unix_socket_fd = connect_to_unix_socket();
    fprintf(stderr, "connected to unix-socket!\n");

    fprintf(stderr, "[libhook] created unix-socket! fd=%d\n", unix_socket_fd);
}

__attribute__((constructor))
static void injected_init(void)
{
    fprintf(stderr, "[libhook] constructor in pid=%d\n", getpid());

    set_timeout(5, my_callback, NULL);
    // int unix_socket_fd = initiate_unix_socket();

    //sleep(5);

    if (hook_plt_symbol("printf", (void *)my_printf,
                        (void **)&real_printf) == 0) {
        fprintf(stderr,
                "[libhook] GOT hook for printf installed, real_printf=%p\n",
                real_printf);
    } else {
        fprintf(stderr, "[libhook] FAILED to hook printf\n");
    }

    // int client_fd = listen_to_unix_socket(unix_socket_fd);
    //
    // fprintf(stderr, "[libhook] Listening to unix-socket! fd=%d\n", client_fd);
}
