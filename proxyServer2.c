#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "threadpool.h"

#define BUFFER_SIZE 8192

char* buildResponseString(int ErrCode);
typedef struct _CLIENT_INFO
{
    struct sockaddr_in sockinfo;
    int sockfd;
    const char* filter_file_path;
} CLIENT_INFO;

char* buildResponseString(int ErrCode) {
    // Get the current date and time in GMT
    time_t rawtime;
    struct tm *info;
    char dateBuffer[80];

    time(&rawtime);
    info = gmtime(&rawtime);
    strftime(dateBuffer, sizeof(dateBuffer), "%a, %d %b %Y %H:%M:%S GMT", info);

    // Calculate the content length (assuming a fixed length of 113 in this example)
    int contentLength = 113;

    // Allocate memory for the response string
    char *responseString = (char *)malloc(512); // Adjust the size as needed

    // Build the response string
    if (400==ErrCode)
    {
    sprintf(responseString, "HTTP/1.1 %d Bad Request\r\n"
                            "Server: webserver/1.0\r\n"
                            "Date: %s\r\n"
                            "Content-Type: text/html\r\n"
                            "Content-Length: 113\r\n"
                            "Connection: close\r\n\r\n"
                            "<HTML><HEAD><TITLE>%d Bad Request</TITLE></HEAD>\r\n"
                            "<BODY><H4>%d Bad request</H4>\r\n"
                            "Bad Request.\r\n</BODY></HTML>",
                            ErrCode, dateBuffer, ErrCode, ErrCode);
    }
    else if (403==ErrCode)
    {
         sprintf(responseString, "HTTP/1.1 %d Forbidden\r\n"
                            "Server: webserver/1.0\r\n"
                            "Date: %s\r\n"
                            "Content-Type: text/html\r\n"
                            "Content-Length: 111\r\n"
                            "Connection: close\r\n\r\n"
                            "<HTML><HEAD><TITLE>%d Forbidden</TITLE></HEAD>\r\n"
                            "<BODY><H4>%d Forbidden</H4>\r\n"
                            "Access denied.\r\n</BODY></HTML>",
                            ErrCode, dateBuffer, ErrCode, ErrCode);
    }
        else if (404==ErrCode)
    {
         sprintf(responseString, "HTTP/1.1 %d Not Found\r\n"
                            "Server: webserver/1.0\r\n"
                            "Date: %s\r\n"
                            "Content-Type: text/html\r\n"
                            "Content-Length: 112\r\n"
                            "Connection: close\r\n\r\n"
                            "<HTML><HEAD><TITLE>%d Not Found</TITLE></HEAD>\r\n"
                            "<BODY><H4>%d Not Found</H4>\r\n"
                            "File not found.\r\n</BODY></HTML>",
                            ErrCode, dateBuffer, ErrCode, ErrCode);
    }
        else if (500==ErrCode)
    {
         sprintf(responseString, "HTTP/1.1 %d Internal Server Error\r\n"
                            "Server: webserver/1.0\r\n"
                            "Date: %s\r\n"
                            "Content-Type: text/html\r\n"
                            "Content-Length: 144\r\n"
                            "Connection: close\r\n\r\n"
                            "<HTML><HEAD><TITLE>%d Internal Server Error</TITLE></HEAD>\r\n"
                            "<BODY><H4>%d Internal Server Error</H4>\r\n"
                            "Some server side error.\r\n</BODY></HTML>",
                            ErrCode, dateBuffer, ErrCode, ErrCode);
    }
        else if (501==ErrCode)
    {
         sprintf(responseString, "HTTP/1.1 %d Not supported\r\n"
                            "Server: webserver/1.0\r\n"
                            "Date: %s\r\n"
                            "Content-Type: text/html\r\n"
                            "Content-Length: 129\r\n"
                            "Connection: close\r\n\r\n"
                            "<HTML><HEAD><TITLE>%d Not supported</TITLE></HEAD>\r\n"
                            "<BODY><H4>%d Not supported</H4>\r\n"
                            "Method is not supported.\r\n</BODY></HTML>",
                            ErrCode, dateBuffer, ErrCode, ErrCode);
    }
    return responseString;
}


int is_ip_allowed(const char *ip_str, const char *filter_entry) {
    struct in_addr ip_addr;
    unsigned int ip, mask, filter_ip, filter_mask;
    char *slash_pos;

    // Convert the IP string to a binary representation
    if (inet_aton(ip_str, &ip_addr) == 0) {
        return 0; // Invalid IP address
    }
    ip = ntohl(ip_addr.s_addr);

    // Parse the filter entry (e.g., 192.168.1.0/24)
    slash_pos = strchr(filter_entry, '/');
    if (slash_pos == NULL) {
        return 0; // Invalid filter entry
    }

    *slash_pos = '\0'; // Temporarily terminate the string to extract the IP part
    if (inet_aton(filter_entry, &ip_addr) == 0) {
        return 0; // Invalid filter IP address
    }
    filter_ip = ntohl(ip_addr.s_addr);

    filter_mask = 0xffffffff << (32 - atoi(slash_pos + 1)); // Calculate the mask from the CIDR notation
    mask = filter_mask;

    // Check if the IP matches the filter entry
    return ((ip & mask) == (filter_ip & mask));
}

int is_host_allowed(const char *host, const char *filter_file) {
    FILE *fp;
    char line[256];
    struct hostent *he;
    struct in_addr **addr_list;
    int i, allowed = 1;

    fp = fopen(filter_file, "r");
    if (fp == NULL) {
        perror("fopen");
        return 1; // Allow if the filter file cannot be opened
    }

    // Check if the host is a domain name or an IP address
    if (inet_addr(host) == INADDR_NONE) {
        // Domain name
        he = gethostbyname(host);
        if (he == NULL) {
            fclose(fp);
            return 0; // Disallow if the host cannot be resolved
        }
        addr_list = (struct in_addr **)he->h_addr_list;
    } else {
        // IP address
        addr_list = (struct in_addr **)malloc(sizeof(struct in_addr *));
        addr_list[0] = (struct in_addr *)malloc(sizeof(struct in_addr));
        inet_aton(host, addr_list[0]);
        addr_list[1] = NULL;
    }

    // Check if the host or any of its IP addresses are in the filter file
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0'; // Remove newline characters

        if (inet_addr(line) != INADDR_NONE) {
            // Line is an IP address or subnet
            for (i = 0; addr_list[i] != NULL; i++) {
                if (is_ip_allowed(inet_ntoa(*addr_list[i]), line)) {
                    allowed = 0;
                    break;
                }
            }
        } else {
            // Line is a domain name
            if (strcasecmp(line, host) == 0) {
                allowed = 0;
                break;
            }
        }
    }

    fclose(fp);
    if (addr_list != (struct in_addr **)he->h_addr_list) {
        free(addr_list[0]);
        free(addr_list);
    }
    return allowed;
}

int forward_request(const char* host, int port, const char* request, int client_fd) {
    int server_fd;
    struct sockaddr_in server_addr;
    struct hostent* server;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return -1;
    }

    server = gethostbyname(host);
    if (server == NULL) {
        herror("gethostbyname");
        close(server_fd);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

    if (connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(server_fd);
        return -1;
    }

    // Send the request to the web server
    if (send(server_fd, request, strlen(request), 0) == -1) {
        perror("send");
        close(server_fd);
        return -1;
    }

    // Receive the response from the web server
    char buffer[BUFFER_SIZE];
    int bytes_received;
    while ((bytes_received = recv(server_fd, buffer, BUFFER_SIZE, 0)) > 0) {
        // Forward the response to the client
        if (send(client_fd, buffer, bytes_received, 0) == -1) {
            perror("send");
            close(server_fd);
            return -1;
        }
    }

    close(server_fd);
    return 0;
}

int handle_request(const char* request, int request_len, int client_fd, const char* filter_file) {
    // Parse the request and check if it's valid
    // ...

    // Check if the request method is GET
    if (strncmp(request, "GET ", 4) != 0) {
        return write(client_fd, buildResponseString(501), strlen(buildResponseString(501)));
    }

    // Extract the host from the request
    char host[256];
    if (sscanf(request, "GET %*s HTTP/%*s\r\nHost: %255s\r\n", host) != 1) {
        return write(client_fd, buildResponseString(400), strlen(buildResponseString(400)));
    }

    // Check if the host is allowed based on the filter file
    if (!is_host_allowed(host, filter_file)) {
        return write(client_fd, buildResponseString(403), strlen(buildResponseString(403)));
    }

    // If the request is valid, forward it to the web server
    if (forward_request(host, 80, request, client_fd) == -1) {
        return write(client_fd, buildResponseString(500), strlen(buildResponseString(500)));
    }

    return 0;
}

void handle_client(void* arg) {
    char buf[BUFFER_SIZE];
    int bread = 0, bwrite = 0;
    CLIENT_INFO cinfo = *(CLIENT_INFO*)arg;
    char* ip = inet_ntoa(cinfo.sockinfo.sin_addr);
    in_port_t port = ntohs(cinfo.sockinfo.sin_port);
    const char* filter_file_path = cinfo.filter_file_path;
    struct timeval tv = {5, 0};

    if (setsockopt(cinfo.sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval)) == -1) {
        perror("setsockopt");
        goto end;
    }

    /* read whatever the client sends */
    bread = read(cinfo.sockfd, buf, BUFFER_SIZE);
    printf("\n\n%s\n\n",buf);
    /* check whether there was an error during read operation */
    if (bread == -1) { // error
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            printf("Read timeout occurred\n");
        else
            perror("read");

        goto end;
    }

    /* check if the client closed the connection */
    if (bread == 0) {
        goto end;
    }

    // Parse the request and handle it
    if (handle_request(buf, bread, cinfo.sockfd, filter_file_path) == -1) {
        // Error handling the request
        bwrite = write(cinfo.sockfd, buildResponseString(400), strlen(buildResponseString(400)));
    }

    /* print client ip and port */
    printf("PORT: %d, IP: %s\n", port, ip);

end:
    close(cinfo.sockfd);
    free(arg);
}

int main(int argc, char* argv[]) {
    struct sockaddr_in serverinfo;
    int wsock;

    if (argc != 5) {
        fprintf(stderr, "Usage: %s <port> <pool-size> <max-requests> <filter>\n", argv[0]);
        exit(1);
    }

    in_port_t port = atoi(argv[1]);
    size_t pool_size = atoi(argv[2]);
    size_t max_tasks = atoi(argv[3]);
    char* filter_file = argv[4];

    threadpool* tp = create_threadpool(pool_size);

    memset(&serverinfo, 0, sizeof(struct sockaddr_in));
    serverinfo.sin_family = AF_INET;
    serverinfo.sin_port = htons(port);
    serverinfo.sin_addr.s_addr = INADDR_ANY;

    if ((wsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    if (bind(wsock, (struct sockaddr*)&serverinfo, sizeof(struct sockaddr_in)) == -1) {
        close(wsock);
        perror("bind");
        return EXIT_FAILURE;
    }

    if (listen(wsock, 5) == -1) {
        close(wsock);
        perror("listen");
        return EXIT_FAILURE;
    }

    int num_of_tasks = 0;
    while (num_of_tasks < max_tasks) {
        CLIENT_INFO* cinfo = (CLIENT_INFO*)malloc(sizeof(CLIENT_INFO));
        socklen_t struct_len = sizeof(struct sockaddr_in);
        cinfo->sockfd = accept(wsock, (struct sockaddr*)&cinfo->sockinfo, &struct_len);
        cinfo->filter_file_path = filter_file;
        num_of_tasks++;
        if (cinfo->sockfd == -1) {
            perror("accept");
            free(cinfo);
            continue;
        }
        dispatch(tp, (void*)handle_client, (void*)cinfo);
    }

    destroy_threadpool(tp);
    close(wsock);
    return EXIT_SUCCESS;
}