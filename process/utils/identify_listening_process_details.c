#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define PROC_NET_TCP "/proc/net/tcp"
#define LISTENING_CONNECTION "0A"

#include "identify_listening_process_details.h"

static int set_listening_inode(int port, fd_details * listening_process_details) {
    FILE *f = fopen(PROC_NET_TCP, "r");

    if (!f) {
        perror("fopen /proc/net/tcp");
        return -1;
    }

    char tcp_connection_info[512];
    // Skip header line
    if (!fgets(tcp_connection_info, sizeof(tcp_connection_info), f)) {
        fclose(f);
        return -1;
    }

    unsigned long inode = 0;

    while (fgets(tcp_connection_info, sizeof(tcp_connection_info), f)) {
        // Tokenize line into columns
        char *columns[32];
        int number_of_columns = 0;

        char *p = strtok(tcp_connection_info, " \t\n");
        while (p && number_of_columns < 32) {
            columns[number_of_columns++] = p;
            p = strtok(NULL, " \t\n");
        }
        if (number_of_columns < 12) {
            continue;
        }

        char *local_connection_info = columns[1];
        char *connection_state = columns[3];

        if (strcmp(connection_state, LISTENING_CONNECTION) != 0) {
            continue;
        }

        // Extract port from local_address (format: HHHHHHHH:PPPP)
        char *colon = strchr(local_connection_info, ':');
        if (!colon) continue;
        unsigned long port_hex = strtoul(colon + 1, NULL, 16);

        if ((int)port_hex != port) {
            continue;
        }

        listening_process_details->inode = strtoul(columns[9], NULL, 10);
        break;
    }

    if (listening_process_details->inode == 0) {
        printf("[Web server identification] No Inode found listening on port %d\n", port);
        return -1;
    }

    fclose(f);
    return 0;
}

static int is_number(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) return 0;
    }
    return 1;
}

static int set_pid_and_fd(const unsigned long inode, fd_details * listening_process_details) {
    // if (inode == 0) {
    //     printf("No matching socket inode found.\n");
    //     return;
    // }

    char target[64];
    snprintf(target, sizeof(target), "socket:[%lu]", inode);

    DIR *proc = opendir("/proc");
    if (!proc) {
        perror("opendir /proc");
        return -1;
    }

    struct dirent *dir_entries;

    pid_t found_pid = 0;
    while (found_pid == 0 && (dir_entries = readdir(proc)) != NULL) {
        if (!is_number(dir_entries->d_name)) {
            continue;
        }

        pid_t pid = (pid_t) atoi(dir_entries->d_name);

        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);

        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) {
            continue; // permission denied or process exited
        }

        struct dirent *fd_ent;
        while (found_pid == 0 && (fd_ent = readdir(fd_dir)) != NULL) {
            if (!is_number(fd_ent->d_name)) continue;

            char link_path[PATH_MAX];
            char link_target[PATH_MAX];

            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_ent->d_name);
            ssize_t len = readlink(link_path, link_target, sizeof(link_target) - 1);
            if (len == -1) {
                continue;
            }
            link_target[len] = '\0';

            if (strcmp(link_target, target) == 0) {
                listening_process_details->pid = pid;
                // const char *str = "12345abc";
                char *endptr;

                const long int listening_fd = strtol(fd_ent->d_name, &endptr, 10);
                if (endptr == fd_ent->d_name || *endptr != '\0') {
                    fprintf(stderr, "Invalid web server FD found!.\n");
                } else {
                    listening_process_details->fd = (int) listening_fd;
                }

                found_pid = 1;
                printf("PID: %d (inode %lu)\n", pid, inode);
            }
        }

        closedir(fd_dir);
    }

    closedir(proc);

    if (found_pid == 0) {
        printf("[Web server identification] No process found for inode %lu (maybe it exited).\n", inode);
        return -1;
    }

    return 0;
}

int identify_listening_process_details(const int port, fd_details * listening_process_details) {
    if (set_listening_inode(port, listening_process_details) != 0) {
        fprintf(stderr, "[Web server identification] No web server on port %d\n", port);
        return -1;
    }

    if (set_pid_and_fd(listening_process_details->inode, listening_process_details) != 0) {
        fprintf(stderr, "[Web server identification] Failed to identify process %d's Inode & FD\n", listening_process_details->pid);
    }

    return 0;
}