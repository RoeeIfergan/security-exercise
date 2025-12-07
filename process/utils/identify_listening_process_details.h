#ifndef PROCESS_IDENTIFYPROCEfprintSSDETAILS_H
#define PROCESS_IDENTIFYPROCESSDETAILS_H

#include <sys/types.h>

typedef struct {
    unsigned long inode;
    pid_t pid;
    int fd;
} fd_details;

int identify_listening_process_details(int port, fd_details * listening_process_details);

#endif //PROCESS_IDENTIFYPROCESSDETAILS_H