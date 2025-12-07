#define _GNU_SOURCE
#include "connection_storage.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>

#include "../../utils/helpers.h"

/*
    Data structure: fd-indexed array

    I want very fast (and little compute) when reading.
    inserting/removing can be a bit slower as it happens only when accepting connections.

    This will work for processes that handle upto tens of thousand of sockets, if the process is expected
    to handle more sockets, then i'd recommend changing the data structure to something more memory efficient.
    more memory efficient == will cost in read/write computation

    for our use case, tens of thousands is plenty!
*/

#define BITS_PER_WORD   (8UL * sizeof(unsigned long))
#define WORD_INDEX(bit) ((bit) / BITS_PER_WORD)
#define BIT_MASK(bit)   (1UL << ((bit) % BITS_PER_WORD))

static inline void bit_set(unsigned long *bits, size_t bit) {
    bits[WORD_INDEX(bit)] |= BIT_MASK(bit);
}

static inline void bit_clear(unsigned long *bits, size_t bit) {
    bits[WORD_INDEX(bit)] &= ~BIT_MASK(bit);
}

static inline int bit_test(const unsigned long *bits, size_t bit) {
    return (bits[WORD_INDEX(bit)] & BIT_MASK(bit)) != 0;
}

int fdt_init(FdTable *t, size_t max_fds)
{
    if (!t || max_fds == 0) {
        errno = EINVAL;
        debug_print(stderr, "[connection Storage hook] Init received invalid argumentsd\n");
        return -1;
    }

    t->max_fds = max_fds;

    t->meta = calloc(max_fds, sizeof(FdMeta));
    if (!t->meta) {
        debug_print(stderr, "[connection Storage hook] Init failed to allocate FD_Table's meta\n");
        return -1;
    }

    size_t words = (max_fds + BITS_PER_WORD - 1) / BITS_PER_WORD;
    t->used = calloc(words, sizeof(unsigned long));
    if (!t->used) {
        debug_print(stderr, "[connection Storage hook] Init failed to allocate FD_Table's used\n");

        free(t->meta);
        t->meta = NULL;
        return -1;
    }

    return 0;
}

int fdt_init_from_rlimit(FdTable *t)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        return -1;
    }

    size_t max_fds = (size_t)rl.rlim_cur;
    if (max_fds == 0) {
        errno = EINVAL;
        return -1;
    }

    return fdt_init(t, max_fds);
}

void fdt_free(FdTable *t)
{
    if (!t) return;
    free(t->meta);
    free(t->used);
    t->meta   = NULL;
    t->used   = NULL;
    t->max_fds = 0;
}

int fdt_set(FdTable *t, int fd, const char data[HOME_IDENTIFIER_LEN])
{
    if (!t || !t->meta || !t->used || !data) {
        errno = EINVAL;
        return -1;
    }
    if (fd < 0 || (size_t)fd >= t->max_fds) {
        errno = EBADF;
        return -1;
    }

    memcpy(t->meta[fd].data, data, HOME_IDENTIFIER_LEN);
    bit_set(t->used, (size_t)fd);
    return 0;
}

FdMeta *fdt_get(FdTable *t, int fd)
{
    if (!t || !t->meta || !t->used) {
        return NULL;
    }
    if (fd < 0 || (size_t)fd >= t->max_fds) {
        return NULL;
    }

    if (!bit_test(t->used, (size_t)fd)) {
        return NULL; // no metadata for this fd
    }

    return &t->meta[fd];
}

void fdt_remove(FdTable *t, int fd)
{
    if (!t || !t->meta || !t->used) {
        return;
    }
    if (fd < 0 || (size_t)fd >= t->max_fds) {
        return;
    }

    bit_clear(t->used, (size_t)fd);
    // optionally zero out data for cleanliness:
    // memset(t->meta[fd].data, 0, sizeof(t->meta[fd].data));
}

int fdt_pop(FdTable *t, int fd, FD_Data out_data)
{
    if (!t || !t->meta || !t->used || !out_data) {
        errno = EINVAL;
        return -1;
    }
    if (fd < 0 || (size_t)fd >= t->max_fds) {
        errno = EBADF;
        return -1;
    }

    size_t b = (size_t)fd;
    if (!bit_test(t->used, b)) {
        // nothing stored for this fd
        errno = ENOENT;  // "No such file or directory" – often used for "not found"
        return -1;
    }

    // copy out the metadata
    memcpy(out_data, t->meta[fd].data, sizeof(FD_Data));

    // mark as unused
    bit_clear(t->used, b);
    // optionally wipe the data for cleanliness:
    // memset(t->meta[fd].data, 0, sizeof(t->meta[fd].data));

    return 0;
}