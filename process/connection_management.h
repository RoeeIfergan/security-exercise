//
// Created by root on 12/6/25.
//

#ifndef PROCESS_CONNECTION_MANAGEMENT_H
#define PROCESS_CONNECTION_MANAGEMENT_H

#define HOME_IDENTIFIER "HOME_IDENTIFIER\n"
#define HOME_IDENTIFIER_LEN sizeof(HOME_IDENTIFIER)

int intercept_connections(int listening_web_server_fd,  int web_server_communication_fd);
int initiate_connection(int injection_connection_fd, int web_server_listening_fd);

#endif //PROCESS_CONNECTION_MANAGEMENT_H