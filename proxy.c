/*
 * Tiny TCP proxy server
 *
 * Author: Krzysztof Klis <krzysztof.klis@gmail.com>
 * Fixes and improvements: Jérôme Poulin <jeromepoulin@gmail.com>
 * IPv6 support: 04/2019 Rafael Ferrari <rafaelbf@hotmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version with the following modification:
 *
 * As a special exception, the copyright holders of this library give you
 * permission to link this library with independent modules to produce an
 * executable, regardless of the license terms of these independent modules,
 * and to copy and distribute the resulting executable under terms of your choice,
 * provided that you also meet, for each linked independent module, the terms
 * and conditions of the license of that module. An independent module is a
 * module which is not derived from or based on this library. If you modify this
 * library, you may extend this exception to your version of the library, but
 * you are not obligated to do so. If you do not wish to do so, delete this
 * exception statement from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/un.h>  // Add support for UNIX domain sockets
#include <sys/time.h>
#ifdef USE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define BUF_SIZE 16384

#define READ  0
#define WRITE 1

#define SERVER_SOCKET_ERROR -1
#define SERVER_SETSOCKOPT_ERROR -2
#define SERVER_BIND_ERROR -3
#define SERVER_LISTEN_ERROR -4
#define CLIENT_SOCKET_ERROR -5
#define CLIENT_RESOLVE_ERROR -6
#define CLIENT_CONNECT_ERROR -7
#define CREATE_PIPE_ERROR -8
#define BROKEN_PIPE_ERROR -9
#define SYNTAX_ERROR -10

typedef enum {TRUE = 1, FALSE = 0} bool;

int check_ipversion(char * address);
int create_socket(int port);
void sigchld_handler(int signal);
void sigterm_handler(int signal);
void server_loop();
void handle_client(int client_sock, struct sockaddr_storage client_addr);
void forward_data(int source_sock, int destination_sock);
void forward_data_ext(int source_sock, int destination_sock, char *cmd);
int create_connection();
int parse_options(int argc, char *argv[]);
void plog(int priority, const char *format, ...);

int server_sock, client_sock, remote_sock, remote_port = 0;
int connections_processed = 0;
char *bind_addr, *remote_host, *cmd_in, *cmd_out;
char *local_domain_socket = NULL, *remote_domain_socket = NULL;
bool foreground = FALSE;
bool use_syslog = FALSE;

#define BACKLOG 20 // how many pending connections queue will hold

/* Program start */
int main(int argc, char *argv[]) {
    int local_port;
    pid_t pid;

    bind_addr = NULL;

    local_port = parse_options(argc, argv);

    if (local_port < 0 && !local_domain_socket) {
        printf("Syntax: %s [-b bind_address] -l local_port -h remote_host -p remote_port [-i \"input parser\"] [-o \"output parser\"] [-f (stay in foreground)] [-s (use syslog)] [-L local_domain_socket] [-R remote_domain_socket]\n", argv[0]);
        return local_port;
    }

    if (use_syslog) {
        openlog("proxy", LOG_PID, LOG_DAEMON);
    }

    if ((server_sock = create_socket(local_port)) < 0) { // start server
        plog(LOG_CRIT, "Cannot run server: %m");
        return server_sock;
    }

    signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
    signal(SIGTERM, sigterm_handler); // handle KILL signal

    if (foreground) {
        server_loop();
    } else {
        switch(pid = fork()) {
            case 0: // deamonized child
                server_loop();
                break;
            case -1: // error
                plog(LOG_CRIT, "Cannot daemonize: %m");
                return pid;
            default: // parent
                close(server_sock);
        }
    }

    if (use_syslog) {
        closelog();
    }

    return EXIT_SUCCESS;
}

/* Parse command line options */
int parse_options(int argc, char *argv[]) {
    int c, local_port = 0;

    while ((c = getopt(argc, argv, "b:l:h:p:i:o:fsL:R:")) != -1) {  // Add new options -L and -R for domain sockets
        switch(c) {
            case 'l':
                local_port = atoi(optarg);
                break;
            case 'b':
                bind_addr = optarg;
                break;
            case 'h':
                remote_host = optarg;
                break;
            case 'p':
                remote_port = atoi(optarg);
                break;
            case 'i':
                cmd_in = optarg;
                break;
            case 'o':
                cmd_out = optarg;
                break;
            case 'f':
                foreground = TRUE;
                break;
            case 's':
                use_syslog = TRUE;
                break;
            case 'L':
                local_domain_socket = optarg;
                break;
            case 'R':
                remote_domain_socket = optarg;
                break;
        }
    }

    if ((local_port && remote_host && remote_port) || local_domain_socket || remote_domain_socket) {
        return local_port;
    } else {
        return SYNTAX_ERROR;
    }
}

int check_ipversion(char * address)
{
/* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1) {
         return AF_INET;
    } else {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1) {
            return AF_INET6;
        }
    }
    return 0;
}


/* Create server socket */
int create_socket(int port) {
    int server_sock, optval = 1;
    int validfamily=0;
    struct addrinfo hints, *res=NULL;
    struct sockaddr_un local;
    char portstr[12];

    if (local_domain_socket) {
        // Domain socket creation
        if ((server_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return SERVER_SOCKET_ERROR;
        }

        memset(&local, 0, sizeof(local));
        local.sun_family = AF_UNIX;
        strncpy(local.sun_path, local_domain_socket, sizeof(local.sun_path) - 1);

        unlink(local_domain_socket);  // Remove any existing socket

        if (bind(server_sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
            close(server_sock);
            return SERVER_BIND_ERROR;
        }

        if (listen(server_sock, BACKLOG) < 0) {
            perror("Error listening on UNIX socket");
            close(server_sock);
            return SERVER_LISTEN_ERROR;
        }

    } else {
        // Existing IPv4/IPv6 socket creation...
        memset(&hints, 0x00, sizeof(hints));
        server_sock = -1;

        hints.ai_flags    = AI_NUMERICSERV;   /* numeric service number, not resolve */
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        /* prepare to bind on specified numeric address */
        if (bind_addr != NULL) {
            /* check for numeric IP to specify IPv6 or IPv4 socket */
            if (validfamily = check_ipversion(bind_addr)) {
                hints.ai_family = validfamily;
                hints.ai_flags |= AI_NUMERICHOST; /* bind_addr is a valid numeric ip, skip resolve */
            }
        } else {
            /* if bind_address is NULL, will bind to IPv6 wildcard */
            hints.ai_family = AF_INET6; /* Specify IPv6 socket, also allow ipv4 clients */
            hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
        }

        sprintf(portstr, "%d", port);

        /* Check if specified socket is valid. Try to resolve address if bind_address is a hostname */
        if (getaddrinfo(bind_addr, portstr, &hints, &res) != 0) {
            return CLIENT_RESOLVE_ERROR;
        }

        if ((server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
            return SERVER_SOCKET_ERROR;
        }

        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
            return SERVER_SETSOCKOPT_ERROR;
        }

        if (bind(server_sock, res->ai_addr, res->ai_addrlen) == -1) {
            close(server_sock);
            return SERVER_BIND_ERROR;
        }

        if (listen(server_sock, BACKLOG) < 0) {
            return SERVER_LISTEN_ERROR;
        }

        if (res != NULL) {
            freeaddrinfo(res);
        }
    }

    return server_sock;
}

/* Send log message to /tmp/proxy.log or syslog */
void plog(int priority, const char *format, ...)
{
    static struct timeval first_log_time = {0, 0};
    struct timeval current_time, delta_time;
    va_list ap;
    FILE *log_file;

    va_start(ap, format);

    // Get the current time
    gettimeofday(&current_time, NULL);

    // Initialize first_log_time with the time of the first log
    if (first_log_time.tv_sec == 0 && first_log_time.tv_usec == 0) {
        first_log_time = current_time;
    }

    // Calculate the delta time
    timersub(&current_time, &first_log_time, &delta_time);

    if (use_syslog) {
        vsyslog(priority, format, ap);
    } else {
        log_file = fopen("/tmp/proxy.log", "a");  // Open the file in append mode
        if (log_file != NULL) {
            // Print the delta time at the beginning of the log entry
            fprintf(log_file, "[%ld.%06ld] ", (long)delta_time.tv_sec, (long)delta_time.tv_usec);
            vfprintf(log_file, format, ap);
            fprintf(log_file, "\n");
            fclose(log_file);
        } else {
            // Fallback to stderr if file opening fails
            fprintf(stderr, "[%ld.%06ld] ", (long)delta_time.tv_sec, (long)delta_time.tv_usec);
            vfprintf(stderr, format, ap);
            fprintf(stderr, "\n");
        }
    }

    va_end(ap);
}

/* Update systemd status with connection count */
void update_connection_count()
{
#ifdef USE_SYSTEMD
    sd_notifyf(0, "STATUS=Ready. %d connections processed.\n", connections_processed);
#endif
}

/* Handle finished child process */
void sigchld_handler(int signal) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

/* Handle term signal */
void sigterm_handler(int signal) {
    close(client_sock);
    close(server_sock);
    exit(0);
}

/* Main server loop */
void server_loop() {
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

#ifdef USE_SYSTEMD
    sd_notify(0, "READY=1\n");
#endif

    plog(LOG_INFO, "server started");

    while (TRUE) {
        update_connection_count();
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        if (fork() == 0) { // handle client connection in a separate process
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        } else {
            connections_processed++;
        }
        close(client_sock);
    }

}


/* Handle client connection */
void handle_client(int client_sock, struct sockaddr_storage client_addr)
{

    if ((remote_sock = create_connection()) < 0) {
        plog(LOG_ERR, "Cannot connect to host: %m");
        goto cleanup;
    }

    if (fork() == 0) { // a process forwarding data from client to remote socket
        if (cmd_out) {
            forward_data_ext(client_sock, remote_sock, cmd_out);
        } else {
            forward_data(client_sock, remote_sock);
        }
        exit(0);
    }

    if (fork() == 0) { // a process forwarding data from remote socket to client
        if (cmd_in) {
            forward_data_ext(remote_sock, client_sock, cmd_in);
        } else {
            forward_data(remote_sock, client_sock);
        }
        exit(0);
    }

cleanup:
    close(remote_sock);
    close(client_sock);
}

/* Forward data between sockets */
void forward_data(int source_sock, int destination_sock) {
    ssize_t n;
    char buffer[BUF_SIZE];

    while ((n = recv(source_sock, buffer, BUF_SIZE, 0)) > 0) {
        plog(LOG_INFO, "Forwarding %ld bytes from source to destination", n);

        if (send(destination_sock, buffer, n, 0) < 0) {
            perror("Error sending data");
            plog(LOG_INFO, "Failed to send %ld bytes to destination", n);
            exit(BROKEN_PIPE_ERROR);
        }
        plog(LOG_INFO, "Successfully forwarded %ld bytes", n);
    }

    if (n < 0) {
        perror("Error reading data");
        plog(LOG_INFO, "Failed to read data from source");
        exit(BROKEN_PIPE_ERROR);
    } else if (n == 0) {
        plog(LOG_INFO, "No more data to forward (source closed connection)");
    }

    shutdown(destination_sock, SHUT_RDWR);
    close(destination_sock);

    shutdown(source_sock, SHUT_RDWR);
    close(source_sock);
    plog(LOG_INFO, "Closed both source and destination sockets");
}


/* Forward data between sockets through external command */
void forward_data_ext(int source_sock, int destination_sock, char *cmd) {
    char buffer[BUF_SIZE];
    int n, i, pipe_in[2], pipe_out[2], pipe_err[2];
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0 || pipe(pipe_err) < 0) {
        plog(LOG_CRIT, "Cannot create pipe: %m");
        exit(CREATE_PIPE_ERROR);
    }
    if (fork() == 0) {
        dup2(pipe_in[READ], STDIN_FILENO);
        dup2(pipe_out[WRITE], STDOUT_FILENO);
        dup2(pipe_err[WRITE], STDERR_FILENO);
        close(pipe_in[WRITE]);
        close(pipe_out[READ]);
        close(pipe_err[READ]);
        n = system(cmd);
        exit(n);
    } else {
        close(pipe_in[READ]);
        close(pipe_out[WRITE]);
        close(pipe_err[WRITE]);
        fd_set read_fds;
        int max_fd = pipe_out[READ] > pipe_err[READ] ? pipe_out[READ] : pipe_err[READ];
        max_fd = max_fd > source_sock ? max_fd : source_sock;

        while (1) {
            FD_ZERO(&read_fds);
            FD_SET(pipe_out[READ], &read_fds);
            FD_SET(pipe_err[READ], &read_fds);
            FD_SET(source_sock, &read_fds);

            if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
                plog(LOG_ERR, "Select error: %m");
                exit(1);
            }

            if (FD_ISSET(source_sock, &read_fds)) {
                n = recv(source_sock, buffer, BUF_SIZE, 0);
                if (n <= 0) break;  // End of input or error
                plog(LOG_INFO, "recv source_sock, write pipe_in (%d)", n);
                if (write(pipe_in[WRITE], buffer, n) < 0) {
                    plog(LOG_ERR, "Cannot write to pipe: %m");
                    exit(BROKEN_PIPE_ERROR);
                }
            }

            if (FD_ISSET(pipe_out[READ], &read_fds)) {
                i = read(pipe_out[READ], buffer, BUF_SIZE);
                plog(LOG_INFO, "read pipe_out, send destination_sock(%d)", i);
                if (i > 0) {
                    send(destination_sock, buffer, i, 0);
                } else if (i == 0) {
                    // EOF on stdout
                    break;
                }
            }

            if (FD_ISSET(pipe_err[READ], &read_fds)) {
                i = read(pipe_err[READ], buffer, BUF_SIZE);
                plog(LOG_INFO, "read pipe_err, send source_sock(%d)", i);
                if (i > 0) {
                    send(source_sock, buffer, i, 0);
                }
            }
        }

        // Cleanup
        shutdown(destination_sock, SHUT_RDWR);
        close(destination_sock);
        shutdown(source_sock, SHUT_RDWR);
        close(source_sock);
        close(pipe_in[WRITE]);
        close(pipe_out[READ]);
        close(pipe_err[READ]);
    }
}


/* Create client connection */
int create_connection() {
    struct addrinfo hints, *res=NULL;
    struct sockaddr_un remote;
    int sock;
    int validfamily=0;
    char portstr[12];

    if (remote_domain_socket) {
        // Domain socket creation
        if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return CLIENT_SOCKET_ERROR;
        }

        memset(&remote, 0, sizeof(remote));
        remote.sun_family = AF_UNIX;
        strncpy(remote.sun_path, remote_domain_socket, sizeof(remote.sun_path) - 1);

        if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
            return CLIENT_CONNECT_ERROR;
        }
    } else {
        // Network socket creation...
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_flags    = AI_NUMERICSERV; /* numeric service number, not resolve */
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        sprintf(portstr, "%d", remote_port);

        /* check for numeric IP to specify IPv6 or IPv4 socket */
        if (validfamily = check_ipversion(remote_host)) {
             hints.ai_family = validfamily;
             hints.ai_flags |= AI_NUMERICHOST;  /* remote_host is a valid numeric ip, skip resolve */
        }

        /* Check if specified host is valid. Try to resolve address if remote_host is a hostname */
        if (getaddrinfo(remote_host, portstr, &hints, &res) != 0) {
            errno = EFAULT;
            return CLIENT_RESOLVE_ERROR;
        }

        if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
            return CLIENT_SOCKET_ERROR;
        }

        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            return CLIENT_CONNECT_ERROR;
        }

        if (res != NULL) {
            freeaddrinfo(res);
        }
    }

    return sock;
}
