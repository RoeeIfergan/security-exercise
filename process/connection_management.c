#include "connection_management.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils/envs.h"
#include "utils/helpers.h"
#include "utils/unix_socket.h"

#define BACKLOG 16
#define MAX_CLIENTS FD_SETSIZE
#define HOME_MSGS_SIZE 100

typedef short int connection_type;
const connection_type EMPTY_CONNECTION_ENUM = 0;
const connection_type USED_CONNECTION_ENUM = 1;
const connection_type IS_HOME_CONNECTION_ENUM = 2;

static int bytes_to_read = sizeof(HOME_IDENTIFIER);

int initiate_connection(const int injection_connection_fd, const int web_server_listening_fd) {
    int * web_server_fd = (int*) calloc(1, sizeof(int));
    *web_server_fd = web_server_listening_fd;

    debug_print(stdout, "Sent listening fd to web server");
    if (write(injection_connection_fd, web_server_fd, sizeof(*web_server_fd)) == -1) {
        printf("Failed to write web server fd to unix socket. fd: %d\n", *web_server_fd);
        free(web_server_fd);

        return -1;
    }

    free(web_server_fd);

    char required_buffer[1] = {0};
    int * listening_fd = (int*) malloc(sizeof(int));

    recv_fd_over_unix_socket(injection_connection_fd, listening_fd, required_buffer, 1);

    if (*listening_fd == -1) {
        printf("Failed to receive initial FD over unix socket. fd: %d\n", *listening_fd);
        return -1;
    }
    debug_print(stdout, "received web server listening fd: %d\n", *listening_fd);

    return *listening_fd;
}

static int is_known_home_connection(const int client_index, const connection_type has_read_from_client_connection[MAX_CLIENTS]) {
    if (has_read_from_client_connection[client_index] == IS_HOME_CONNECTION_ENUM) {
        return 1;
    }

    return 0;
}

static void set_is_home_connection(const int client_index, connection_type has_read_from_client_connection[MAX_CLIENTS]) {
    has_read_from_client_connection[client_index] = IS_HOME_CONNECTION_ENUM;
}

static void set_has_read_connection_data(const int client_index, connection_type has_read_from_client_connection[MAX_CLIENTS]) {
    has_read_from_client_connection[client_index] = USED_CONNECTION_ENUM;
}

static int is_new_home_connection(const char * initial_data) {
    if (strcmp(HOME_IDENTIFIER, initial_data) == 0) {
        return 1;
    }

    return 0;
}

static int should_read_client_data(
    const int client_index,
    const int * client_fds,
    const connection_type * has_read_from_client_connection
    ) {

    if (
        client_fds[client_index] != -1 && (
            has_read_from_client_connection[client_index] == EMPTY_CONNECTION_ENUM
            || is_known_home_connection(client_index, has_read_from_client_connection)
            )
        ) {
        return 1;
    }

    return 0;
}

static int add_client(
    const int client_fd,
    int * client_fds,
    char client_initial_msgs[MAX_CLIENTS][bytes_to_read]
    ) {
    int client_index;

    for (client_index = 0; client_index < MAX_CLIENTS; ++client_index) {
        if (client_fds[client_index] < 0) {
            client_fds[client_index] = client_fd;
            break;
        }
    }

    memset(client_initial_msgs[client_index], 0, bytes_to_read);

    return client_index;
}

static void remove_client(
    const int client_index,
    int * client_fds,
    char client_initial_msgs[MAX_CLIENTS][bytes_to_read],
    connection_type * has_read_from_client_connection
    ) {
    client_fds[client_index] = -1;
    memset(client_initial_msgs[client_index], 0, bytes_to_read);
    has_read_from_client_connection[client_index] = EMPTY_CONNECTION_ENUM;
}

static int add_clients_to_fd_set (const int client_fds[MAX_CLIENTS], fd_set * read_fds, int max_fd) {
    for (int client_index = 0; client_index < MAX_CLIENTS; ++client_index) {
        int fd = client_fds[client_index];
        if (fd >= 0) {
            FD_SET(fd, read_fds);
            if (fd > max_fd) {
                max_fd = fd;
            }
        }
    }

    return max_fd;
}

static void accept_incoming_connections(
    const int listening_web_server_fd,
    const fd_set * read_fds,
    int client_fds[MAX_CLIENTS],
    char client_initial_msgs[MAX_CLIENTS][bytes_to_read]
    ) {
    if (FD_ISSET(listening_web_server_fd, read_fds) == 0) {
        return;
    }


    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    const int new_fd = accept(listening_web_server_fd, (struct sockaddr *)&cli_addr, &cli_len);

    if (new_fd < 0) {
        fprintf(stderr, "[Connection Manager] Failed to accept client\n");

        return;
    }

    fprintf(stderr, "[Connection Manager] Accepted client\n");
    fprintf(stderr, "[Connection Manager] New connection from %s:%d (fd=%d)\n",
           inet_ntoa(cli_addr.sin_addr),
           ntohs(cli_addr.sin_port),
           new_fd);

    const int client_index = add_client(new_fd, client_fds, client_initial_msgs);

    if (client_index == MAX_CLIENTS) {
        fprintf(stderr, "Too many clients, closing fd=%d\n", new_fd);
        close(new_fd);
    }
}

void talk_to_home(
    const int client_index,
    const int client_fd,
    char client_data[bytes_to_read],
    const ssize_t received_bytes,
    int client_fds[MAX_CLIENTS],
    char client_initial_msgs[MAX_CLIENTS][bytes_to_read],
    connection_type has_read_from_client_connection[MAX_CLIENTS]
    ) {

    size_t msg_length = strlen(client_data);
    if (msg_length > 0 && client_data[msg_length - 1] == '\n') {
        client_data[msg_length - 1] = '\0';
    }

    printf("[Home manager] Receieved: \"%s\"\n", client_data);

    fprintf(stderr, "[process, fd=%d] received %zd bytes from home: ", client_fd, received_bytes);
    fwrite(client_data, 1, received_bytes, stderr);
    fprintf(stderr, "\n");

    // Echo back exactly what we received
    ssize_t total = 0;
    while (total < received_bytes) {
        const ssize_t sent = send(client_fd, client_data + total, received_bytes - total, 0);
        if (sent <= 0) {
            perror("send");
            printf("Closing fd=%d due to send error\n", client_fd);
            close(client_fd);
            remove_client(client_index, client_fds, client_initial_msgs, has_read_from_client_connection);
            break;
        }
        total += sent;
    }
}

void handle_existing_connections(
    const int web_server_communication_fd,
    const fd_set * read_fds,
    int client_fds[MAX_CLIENTS],
    connection_type has_read_from_client_connection[MAX_CLIENTS],
    char client_initial_msgs[MAX_CLIENTS][bytes_to_read])
{
    /* Handle existing clients */
    for (int client_index = 0; client_index < MAX_CLIENTS; ++client_index) {
        int client_fd = client_fds[client_index];
        if (client_fd < 0) {
            continue;
        }

        int debug_me = FD_ISSET(client_fd, read_fds);

        if (
            FD_ISSET(client_fd, read_fds)
            && should_read_client_data(client_index, client_fds, has_read_from_client_connection) == 1) {

            char client_data[bytes_to_read];
            memset(client_data, '\0', bytes_to_read);

            ssize_t received_bytes;


            if (!is_known_home_connection(client_index, has_read_from_client_connection)) {
                received_bytes = read_n(client_fd, client_data, sizeof(client_data));
                set_has_read_connection_data(client_index, has_read_from_client_connection);
            } else
            {
                received_bytes = recv(client_fd, client_data, HOME_MSGS_SIZE, 0);
                // read_n(client_fd, client_data, sizeof(client_data));
            }

            if (received_bytes <= 0) {
                if (received_bytes < 0) {
                    fprintf(stderr, "Failed to read client data, fd=%d\n", client_fd);
                }
                fprintf(stderr, "client closed connection, fd=%d\n", client_fd);
                // EMPTY_CONNECTION_ENUM

                close(client_fd);
                remove_client(client_index, client_fds, client_initial_msgs, has_read_from_client_connection);
            } else {
                if (
                    is_new_home_connection(client_data)
                    || is_known_home_connection(client_index, has_read_from_client_connection)
                    ) {
                    set_is_home_connection(client_index, has_read_from_client_connection);
                    talk_to_home(
                        client_index,
                        client_fd,
                        client_data,
                        received_bytes,
                        client_fds,
                        client_initial_msgs,
                        has_read_from_client_connection
                    );
                } else {
                    send_fd_over_unix_socket(
                        web_server_communication_fd,
                        client_fds[client_index],
                        client_data,
                        bytes_to_read);
                    remove_client(client_index, client_fds, client_initial_msgs, has_read_from_client_connection);
                    /*
                     *  ======
                     *   Note
                     *  ======
                     *
                     *  Can't close FD because we don't know if the web server accepted it.
                     *  If we close it before the web server accepting it, There isn't a reference
                     *  to the socket, therefore the os will close the connection which is unwanted
                     */
                }
            }
        }
    }
}

int intercept_connections(int listening_web_server_fd, int web_server_communication_fd)
{
    if (listening_web_server_fd < 0) {
        printf("Received invalid fd to intercept. fd: %d\n", listening_web_server_fd);

        return 1;
    }

    char client_initial_msgs[MAX_CLIENTS][bytes_to_read];
    memset(client_initial_msgs, 0, sizeof(client_initial_msgs));

    connection_type has_read_from_client_connection[MAX_CLIENTS];
    int client_fds[MAX_CLIENTS];

    for (int client_index = 0; client_index < MAX_CLIENTS; ++client_index) {
        client_fds[client_index] = -1;
    }

    printf("[Connection manager (pid:%d)]: Listening on port %d...\n", getpid(), PORT);

    while (1) {
        fd_set read_fds;
        int max_fd = listening_web_server_fd;

        FD_ZERO(&read_fds);
        FD_SET(listening_web_server_fd, &read_fds);

        max_fd = add_clients_to_fd_set(client_fds, &read_fds, max_fd);

        const int rc = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "[connection manager] Failed to read fgrom select\n");
            break;
        }

        accept_incoming_connections(
            listening_web_server_fd,
            &read_fds,
            client_fds,
            client_initial_msgs
        );

        handle_existing_connections(
            web_server_communication_fd,
            &read_fds,
            client_fds,
            has_read_from_client_connection,
            client_initial_msgs
        );


    }

    // close(listening_web_server_fd);
    return 0;
}