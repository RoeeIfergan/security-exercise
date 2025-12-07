#define _GNU_SOURCE

#include "hook_read.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <dlfcn.h>

#include "hook_global_state.h"
#include "../../../utils/helpers.h"

ssize_t my_recv_with_stash(int sock_fd, void *buffer, size_t len, int flags)
{

    FD_Data stashed_data;
    size_t stash_len = 0;

    if (fdt_pop(&fd_table_storage, sock_fd, stashed_data) == 0) {
        stash_len = strnlen((char *)stashed_data, sizeof(stashed_data));
    }

    // Clamp stash_len to len so we don't overflow the buffer param
    if (stash_len > len) {
        stash_len = len;
    }

    char *dst = (char *) buffer;
    size_t total = 0;

    if (stash_len > 0) {
        memcpy(dst, stashed_data, stash_len);
        dst   += stash_len;
        total += stash_len;
    }

    size_t additional_bytes_to_read = 0;
    if (len > total) {
        additional_bytes_to_read = len - total;
    }

    if (additional_bytes_to_read == 0) {
        return (ssize_t) stash_len;
    }

    ssize_t bytes_read = 0;
    bytes_read = real_recv(sock_fd, dst, additional_bytes_to_read, flags);

    if (bytes_read < 0) {
        debug_print(stderr, "[read-hook] Failed to read from web server requested socket\n");
        return -1;
    }
    total += (size_t)bytes_read;

    return (ssize_t)total;
}

/*
 *  ==============
 *   Known Issue
 *  ==============
 *
 *  Due to the current data strcture being an index-array,
 *  if the len param is smaller than sizeof(FD_DATA) data will be lost..
 *
 *  This is unlinkely to happen since a https server should read the protocol
 *  headers that are greate (in size) than sizeof(FD_DATA) but at the end
 *  of the day, this can change due to different web server implementations
 *
 *  In addition, if our process couldn't read sizeof(FD_DATA) bytes for some reason,
 *  invalid bytes will be injected to the buffer param. This shouldn't happen
 *  because our process reads (with blocking) until sizeof(FD_DATA) is read.
 *
 * This is also unlikely to happen since a http client should send the http protocol
 * headers and anything else would be considered invalid..
 *
 */

ssize_t my_recv(int sock_fd, void *buffer, size_t len, int flags)
{
    fprintf(stdout, "[read-hook] recv called\n");

    if (!real_recv) {
        real_recv = (recv_f_type)dlsym(RTLD_NEXT, "recv");
        if (!real_recv) {
            debug_print(stderr, "[read-hook] Failed to read from read_recv!\n");

            return -1;
        }
    }

    fprintf(stdout, "[read-hook] reading from unix socket..\n");

    ssize_t total_read_bytes = my_recv_with_stash(sock_fd, buffer, len, flags);

    fprintf(stdout, "[read-hook] read from unix socket\n");

    if (DEBUG == 1) {
        fprintf(stderr, "[read-hook] Read from fd=%d: ", sock_fd);

        fwrite(buffer, 1, total_read_bytes, stdout);
        fprintf(stdout, "\"\n");

    }

    return total_read_bytes;
}