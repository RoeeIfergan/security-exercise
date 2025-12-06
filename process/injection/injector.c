#define _GNU_SOURCE

#include <elf.h>        // NT_PRSTATUS
#include <dlfcn.h>      // dlopen, dlsym
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/uio.h>    // struct iovec
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h> // struct user_pt_regs (AArch64)

#include "injector.h"

#include "../utils/helpers.h"

// ---------------------------------------------------------------------
// /proc/<pid>/maps helpers
// ---------------------------------------------------------------------

// Find base address of a mapping whose line contains `library` substring.
unsigned long long findLibrary(const char *library, pid_t pid) {
    char mapFilename[128];
    char buffer[4096];
    FILE *fd;
    unsigned long long addr = 0;

    if (pid == -1) {
        snprintf(mapFilename, sizeof(mapFilename), "/proc/self/maps");
    } else {
        snprintf(mapFilename, sizeof(mapFilename), "/proc/%d/maps", pid);
    }

    fd = fopen(mapFilename, "r");
    if (!fd) {
        return 0;
    }

    while (fgets(buffer, sizeof(buffer), fd)) {
        if (strstr(buffer, library)) {
            addr = strtoull(buffer, NULL, 16);
            break;
        }
    }

    fclose(fd);
    return addr;
}

int has_mapping(pid_t pid, const char *lib_name) {
    char path[64];
    char line[512];
    FILE *fileP;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    fileP = fopen(path, "r");
    if (!fileP) return 0;

    int found = 0;
    while (fgets(line, sizeof(line), fileP)) {
        if (strstr(line, lib_name)) {
            found = 1;
            break;
        }
    }
    fclose(fileP);
    return found;
}

// Rough heuristic: if ld-linux is mapped, process is dynamically linked.
int is_dynamic_process(pid_t pid) {
    if (has_mapping(pid, "ld-linux") || has_mapping(pid, "/ld-")) {
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------
// Find an executable region in target (to reuse as scratch / code space)
// ---------------------------------------------------------------------

void *freeSpaceAddr(pid_t pid) {
    FILE *fp;
    char filename[64];
    char line[850];
    unsigned long addr = 0, end = 0;
    char perms[8];

    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    if ((fp = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "[!] Error: could not open maps file for PID %d\n", pid);
        exit(1);
    }

    while (fgets(line, sizeof(line), fp)) {
        // Format: start-end perms ...
        if (sscanf(line, "%lx-%lx %7s", &addr, &end, perms) >= 2) {
            if (strchr(perms, 'x') != NULL) {
                // first executable region
                break;
            }
        }
    }

    fclose(fp);
    return (void *)addr;
}

// ---------------------------------------------------------------------
// ptrace memory helpers (read/write arbitrary bytes)
// ---------------------------------------------------------------------

void ptraceRead(pid_t pid, unsigned long long addr, void *data, int len) {
    long word;
    int i;
    char *p = (char *)data;

    for (i = 0; i < len; i += sizeof(word)) {
        errno = 0;
        word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(addr + i), NULL);
        if (word == -1 && errno != 0) {
            perror("[!] Error reading process memory");
            exit(1);
        }
        int chunk = (len - i >= (int)sizeof(word)) ? (int)sizeof(word) : (len - i);
        memcpy(p + i, &word, chunk);
    }
}

void ptraceWrite(pid_t pid, unsigned long long addr, const void *data, int len) {
    long word;
    int i;

    for (i = 0; i < len; i += sizeof(word)) {
        memset(&word, 0, sizeof(word));
        int chunk = (len - i >= (int)sizeof(word)) ? (int)sizeof(word) : (len - i);
        memcpy(&word, (const char *)data + i, chunk);
        if (ptrace(PTRACE_POKETEXT, pid, (void *)(addr + i),
                   (void *)word) == -1) {
            perror("[!] Error writing to process memory");
            exit(1);
        }
    }
}

// ---------------------------------------------------------------------
// AArch64 register access via PTRACE_GETREGSET / PTRACE_SETREGSET
// ---------------------------------------------------------------------

int get_regs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len  = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_GETREGSET");
        return -1;
    }
    return 0;
}

int set_regs(pid_t pid, const struct user_pt_regs *regs) {
    struct iovec iov;
    iov.iov_base = (void *)regs;
    iov.iov_len  = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) == -1) {
        perror("PTRACE_SETREGSET");
        return -1;
    }
    return 0;
}

// ---------------------------------------------------------------------
// Resolve remote dlopen address in target
// Works if dlopen lives in libdl (older glibc) or in libc (modern glibc).
// ---------------------------------------------------------------------

typedef struct
{
    void * lib_handle;
    const char *lib_name;
    void *dlopen;
} dlopen_info;

int get_local_dlopen(dlopen_info * dlopen_struct)
{
    if (!dlopen_struct)
    {
        return -1;
    }

    void *local_lib_handle = NULL;
    void *local_dlopen = NULL;

    // 1. Prefer libc.so.6 (modern glibc: dlopen lives here)
    local_lib_handle = dlopen("libc.so.6", RTLD_LAZY);
    if (local_lib_handle) {
        local_dlopen = dlsym(local_lib_handle, "dlopen");
        if (local_dlopen) {

            dlopen_struct->lib_handle = local_lib_handle;
            dlopen_struct->dlopen = local_dlopen;
            dlopen_struct->lib_name = "libc.so.6";

            debug_print(stderr, "[V]: Loaded libc.so.6 successfully!");
            return 0;
        }
    }

    debug_print(stderr, "[?]: Failed to load libc.so.6, trying fallback (libdl.so.2)");

    local_lib_handle = dlopen("libdl.so.2", RTLD_LAZY);
    if (!local_lib_handle) {
        fprintf(stderr,
                "[X] Could not open libc.so.6 or libdl.so.2: %s\n",
                dlerror());
        return -1;
    }

    local_dlopen = dlsym(local_lib_handle, "dlopen");

    if (!local_dlopen) {
        fprintf(stderr, "[X] dlsym(\"dlopen\") failed: %s\n", dlerror());
        return -1;
    }

    dlopen_struct->lib_handle = local_lib_handle;
    dlopen_struct->dlopen = local_dlopen;
    dlopen_struct->lib_name = "libdl.so.2";

    debug_print(stderr, "[V]: Loaded libdl.so.2 successfully!");

    return 0;
}

int resolve_remote_dlopen(pid_t pid, void **remote_func_out) {
    if (!is_dynamic_process(pid)) {
        fprintf(stderr, "[X] Target %d appears to be static; no loader present.\n", pid);
        return -1;
    }

    dlopen_info * local_dlopen = (dlopen_info*) malloc(sizeof(dlopen_info));

    if (local_dlopen == NULL) {
        fprintf(stderr, "[X] Failed to allocate memory for dlopen_info!\n");
        return -1;
    }

    if (get_local_dlopen(local_dlopen) == -1) {
        fprintf(stderr, "[X] Failed to load local dlopen!\n");
        free(local_dlopen);

        return -1;
    }

    // 3. Get base of that library in our own process using /proc/self/maps.
    unsigned long long local_lib_base = findLibrary(local_dlopen->lib_name, -1);
    if (!local_lib_base) {
        fprintf(stderr, "[!] Could not find %s base in self.\n", local_dlopen->lib_name);
        free(local_dlopen);
        return -1;
    }

    printf("[*] local dlopen lib:   %s\n", local_dlopen->lib_name);
    printf("[*] local dlopen:       %p\n", local_dlopen->dlopen);
    printf("[*] local dlopen base:  0x%llx\n", local_lib_base);

    unsigned long long offset =
        (unsigned long long)(uintptr_t)local_dlopen->dlopen - local_lib_base;

    // 4. In the target, find the corresponding library and add the offset.
    unsigned long long remote_lib_base = 0;

    if (strcmp(local_dlopen->lib_name, "libc.so.6") == 0) {
        // In /proc/<pid>/maps it might appear as "libc.so.6" or "libc-2.xx.so"
        remote_lib_base = findLibrary("libc.so.6", pid);
        if (!remote_lib_base) remote_lib_base = findLibrary("libc.so", pid);
        if (!remote_lib_base) remote_lib_base = findLibrary("libc-", pid);
    } else { // libdl.so.2
        remote_lib_base = findLibrary("libdl.so.2", pid);
        if (!remote_lib_base) remote_lib_base = findLibrary("libdl.so", pid);
        if (!remote_lib_base) remote_lib_base = findLibrary("libdl-", pid);
    }

    if (!remote_lib_base) {
        fprintf(stderr, "[!] Could not find matching %s in target process.\n",
                local_dlopen->lib_name);
        free(local_dlopen);
        return -1;
    }

    void *remote_dlopen = (void *)(remote_lib_base + offset);

    printf("[*] remote dlopen base: 0x%llx\n", remote_lib_base);
    printf("[*] remote dlopen addr: %p\n", remote_dlopen);

    *remote_func_out = remote_dlopen;

    free(local_dlopen);
    return 0;
}


// ---------------------------------------------------------------------
// Main injection logic for AArch64
// ---------------------------------------------------------------------

static void inject_so_into_process(pid_t pid, const char *so_path) {
    struct user_pt_regs oldregs, regs;
    int status;
    unsigned char backup[64];
    void *freeaddr;
    void *remote_dlopen = NULL;

    if (resolve_remote_dlopen(pid, &remote_dlopen) == -1) {
        fprintf(stderr, "[!] Could not resolve remote dlopen.\n");
        return;
    }

    // Attach
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH");
        exit(1);
    }
    if (waitpid(pid, &status, WUNTRACED) == -1) {
        perror("waitpid attach");
        exit(1);
    }

    // Save regs
    if (get_regs(pid, &oldregs) == -1) {
        exit(1);
    }
    memcpy(&regs, &oldregs, sizeof(regs));

    // Choose executable region
    freeaddr = freeSpaceAddr(pid);
    printf("[*] Using executable region at %p for scratch\n", freeaddr);

    ptraceRead(pid, (unsigned long long)freeaddr, backup, sizeof(backup));

    // Layout:
    //   freeaddr      : so_path string (<=48 bytes)
    //   freeaddr + 48 : BRK instruction
    size_t path_len = strlen(so_path) + 1;
    if (path_len > 48) {
        fprintf(stderr, "[!] so_path too long for this PoC (max 48 bytes)\n");
        exit(1);
    }
    ptraceWrite(pid, (unsigned long long)freeaddr, so_path, (int)path_len);

    unsigned int brk_insn = 0xd4200000; // AArch64 BRK #0
    ptraceWrite(pid, (unsigned long long)freeaddr + 48,
                &brk_insn, sizeof(brk_insn));

    // AArch64 ABI:
    //   x0 = arg0 (path)
    //   x1 = arg1 (mode = RTLD_LAZY = 2)
    //   x30 = return address (BRK)
    //   pc = dlopen address
    regs.regs[0]  = (unsigned long long)freeaddr;
    regs.regs[1]  = 2;
    regs.regs[30] = (unsigned long long)freeaddr + 48;
    regs.pc       = (unsigned long long)remote_dlopen;

    if (set_regs(pid, &regs) == -1) {
        exit(1);
    }

    // Continue and wait for SIGTRAP from BRK
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("PTRACE_CONT");
        exit(1);
    }

    if (waitpid(pid, &status, WUNTRACED) == -1) {
        perror("waitpid after CONT");
        exit(1);
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // dlopen return in x0
        if (get_regs(pid, &regs) == -1) {
            exit(1);
        }

        unsigned long long handle = regs.regs[0];
        if (handle != 0) {
            printf("[*] Library injected successfully; handle = %p\n",
                   (void *)handle);
        } else {
            printf("[!] dlopen returned NULL; injection failed\n");
        }

        // Restore original code + regs, detach
        ptraceWrite(pid, (unsigned long long)freeaddr, backup, sizeof(backup));
        if (set_regs(pid, &oldregs) == -1) {
            exit(1);
        }
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            perror("PTRACE_DETACH");
            exit(1);
        }
    } else {
        fprintf(stderr, "[!] Unexpected stop (not SIGTRAP), status=0x%x\n", status);
        exit(1);
    }
}

// ---------------------------------------------------------------------
// public entry point (called from your main.c)
// ---------------------------------------------------------------------

//TODO change /tmp/inject.so permissions to 777

void inject(pid_t pid) {
    const char *so_path = "/tmp/inject.so";

    printf("[*] AArch64 ptrace + dlopen-style injector\n");
    printf("[*] Target PID: %d, SO: %s\n", pid, so_path);

    inject_so_into_process(pid, so_path);
}
