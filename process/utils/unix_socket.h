#ifndef PROCESS_UNIX_SOCKET_H
#define PROCESS_UNIX_SOCKET_H

int initiate_unix_socket();

int listen_to_unix_socket(int fd);

int connect_to_unix_socket();
#endif //PROCESS_UNIX_SOCKET_H