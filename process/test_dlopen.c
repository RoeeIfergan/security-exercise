// test_dlopen.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int main(void) {
    void *h = dlopen("/tmp/inject.so", RTLD_NOW);
    if (!h) {
        printf("dlopen failed: %s\n", dlerror());
        return 1;
    }
    printf("dlopen ok: %p\n", h);
    return 0;
}