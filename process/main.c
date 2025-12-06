#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>
#include "injection/injector.h"
#include <unistd.h>


#include "./utils/identify_listening_process_details.h"
#include "./utils/unix_socket.h"


int main(int argc, char **argv) {
    unsigned long long remoteLib, localLib;
    void *dlopenAddr = NULL;
    void *libdlAddr  = NULL;
    int port = 3000;

    printf("Looking for process listening on TCP port %d...\n", port);

    int unix_socket_fd = initiate_unix_socket();

    fd_details * listening_socket_details = (fd_details*) calloc(1, sizeof(fd_details));
    identify_listening_process_details(3000, listening_socket_details);

    if (listening_socket_details->pid == 0) {
        printf("No listening socket found on port %d (IPv4, /proc/net/tcp).\n", port);
        return 0;
    }

    printf("Found listening socket inode: %lu\n", listening_socket_details->inode);

    // pid_t target = listening_socket_details->pid;

    inject(listening_socket_details->pid);

    // int client_fd = connect_to_unix_socket();

    int client_fd = listen_to_unix_socket(unix_socket_fd);

    fprintf(stdout, "Connection to client fd from unix socket! %d", client_fd);

    while (1) {
        sleep(1);
        fprintf(stdout, "Slept for 1 second %d", client_fd);
    }
    // Load libdl in our own process
    // libdlAddr = dlopen("libdl.so.2", RTLD_LAZY);
    // if (libdlAddr == NULL) {
    //     printf("[!] Error opening libdl.so.2: %s\n", dlerror());
    //     exit(1);
    // }
    // printf("[*] libdl.so.2 loaded at address %p\n", libdlAddr);
    //
    // // Get address of dlopen()
    // dlopenAddr = dlsym(libdlAddr, "dlopen");
    // if (dlopenAddr == NULL) {
    //     printf("[!] Error locating dlopen() function\n");
    //     exit(1);
    // }
    // printf("[*] dlopen() found at address %p\n", dlopenAddr);
    //
    // // Find base of libdl in the target process
    // // (adjust string to match your system's libdl mapping name)
    // remoteLib = findLibrary("libdl.so.2", target);
    // printf("[*] libdl located in PID %d at address %p\n",
    //        target, (void *)remoteLib);
    //
    // // Find base of libdl in our own process
    // localLib = findLibrary("libdl.so.2", -1);
    //
    // // Adjust dlopenAddr for target ASLR:
    // // remote_dlopen = remoteLib + (dlopenAddr - localLib)
    // dlopenAddr = (void *)(remoteLib + ((unsigned long long)dlopenAddr - localLib));
    //
    // printf("[*] dlopen() offset in libdl: 0x%llx bytes\n",
    //        (unsigned long long)((unsigned long long)dlopenAddr - remoteLib));
    // printf("[*] dlopen() in target process at address %p\n", dlopenAddr);
    //
    // // Inject our shared library into the target process
    // inject(target, dlopenAddr);

    return 0;
}
