#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include "threadpool.h"
#include <arpa/inet.h>
#include <ctype.h>

int lines_count = 0;
char** filter ;

int isNum(char* num){
    for(int i=0;i<strlen(num);i++){
        if(!isdigit(num[i])){
            return 0;
        }
    }
    return 1;
}

char* errors(char* error_num, char* error_type){
    char* x = (char*)malloc(sizeof(char)*5000);
    char* y = (char*)malloc(sizeof(char)*5000);
    char buffer[5000];
    time_t t;
    struct tm *time_info;
    sprintf(y,"<HTML><HEAD><TITLE>%s %s</TITLE></HEAD>\r\n<BODY><H4>%s %s</H4>\r\n", error_num, error_type, error_num, error_type);
    if(strcmp(error_num,"400")==0){
        strcat(y, "Bad Request.\r\n</BODY></HTML>");
    }
    else if(strcmp(error_num,"500")==0){
        strcat(y, "Some server side error.\r\n</BODY></HTML>");
    }
    else if(strcmp(error_num,"501")==0){
        strcat(y, "Method is not supported.\r\n</BODY></HTML>");
    }
    else if(strcmp(error_num,"403")==0){
        strcat(y, "Access denied.\r\n</BODY></HTML>");
    }
    else if(strcmp(error_num,"404")==0){
        strcat(y, "File not found.\r\n</BODY></HTML>");
    }
    y[strlen(y)]='\0';
    if(time(&t)==-1){
        perror("error: time\n");
        free(x);
        free(y);
        return "";
    }
    time_info = gmtime(&t);
    if(time_info==NULL){
        perror("error: gmtime\n");
        free(x);
        free(y);
        return "";
    }
    strftime(buffer,sizeof(buffer),"%a, %d %b %Y %H:%M:%S",time_info);
    sprintf(x, "HTTP/1.1 %s %s\r\nServer: webserver/1.0\r\nDate: %s GMT\r\nContent-Type: text/html\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n%s", error_num, error_type, buffer, strlen(y), y);
    x[strlen(x)]='\0';
    free(y);
    return x;
}

char*  deleteEncoding(char* buffer){
    char* without_encoding = (char*)malloc(sizeof(char) * strlen(buffer));
    without_encoding[0] = '\0';
    int count = 0;
    char* c;
    c = strstr(buffer, "\r\nAccept-Encoding: gzip, deflate");
    if(c == NULL){
        free(without_encoding);
        return buffer;
    }else{
        int i = 0;
        for(i=0;i<c-buffer;i++){
            without_encoding[count] = buffer[i];
            count +=1;
        }
        for(int j=i+strlen("\r\nAccept-Encoding: gzip, deflate");j<strlen(buffer);j++){
            without_encoding[count] = buffer[j];
            count +=1;
        }
        without_encoding[count] = '\0';
    }
    return without_encoding; 
}

char* closingConnection(char* buffer){
    char* closedBuffer = (char*)malloc(sizeof(char) * strlen(buffer)*2);
    strcpy(closedBuffer, "\0");
    char* c;
    char* c2;
    c = strstr(buffer, "\r\nConnection: close");
    c2 = strstr(buffer, "\r\nConnection: keep-alive");
    if(c != NULL){
        free(closedBuffer);
        return buffer;
    }else{
        int count = 0;
        int RNcount = 0;
        if(c2 == NULL){
            int i=0;
            for(i=0;i<strlen(buffer);i++){
                if(RNcount == 2){
                    break;
                }
                closedBuffer[count] = buffer[i];
                count += 1;
                if(i!=0){
                    if(buffer[i-1] == '\r' && buffer[i] == '\n'){
                        RNcount += 1;
                    }
                }
            }
            closedBuffer[count] = '\0';
            strcat(closedBuffer, "Connection: close\r\n");
            count += strlen("Connection: close\r\n");
            for(int j=i;j<strlen(buffer);j++){
                closedBuffer[count] = buffer[j];
                count+=1;
            }
            closedBuffer[count] = '\0';
        }else{
            int x = strlen("\r\nConnection: keep-alive");
            int i=0;
            for(i=0;i<c2 - buffer;i++){
                closedBuffer[count] = buffer[i];
                count+=1;
            }
            closedBuffer[count] = '\0';
            strcat(closedBuffer, "\r\nConnection: close");
            count+=strlen("\r\nConnection: close");
            for(int j=i+x;j<strlen(buffer);j++){
                closedBuffer[count] = buffer[j];
                count+=1;
            }
            closedBuffer[count] = '\0';
        }
    } 
    return closedBuffer;
}

char** readFilter(char* filePath){
    FILE* file;
    if((file = fopen(filePath,"r"))==NULL){
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(0);
    }

    fseek(file,0,SEEK_END);
    int filterSize = ftell(file);
    fseek(file,0,SEEK_SET);
    char buffer[filterSize];
    int max = 0;
    while(fgets(buffer, filterSize+1, file) != NULL){
        if((int)strlen(buffer) > max){
            max = (int)strlen(buffer);
        }
        if(strcmp(buffer,"\n")==0){
            continue;
        }
        lines_count+=1;
        for(int i=0;i<strlen(buffer);i++){
            buffer[i] = '\0';
        }
    }
    fseek(file,0,SEEK_SET);
    char** filter = (char**)malloc(sizeof(char*)*lines_count);
    for(int i=0;i<lines_count;i++){
        filter[i] = (char*)malloc(sizeof(char)*2*max);
        strcpy(filter[i], "\0");
    }
    int count = 0;
    while(count < lines_count){
        if(fgets(filter[count],filterSize+1, file) == NULL){
            perror("error: fgets\n");
            fclose(file);
            exit(0);
        }
        if(strcmp(filter[count], "\n")==0){
            strcpy(filter[count],"\0");
            continue;
        }
        count+=1;
    }
    for(int i=0;i<lines_count;i++){
        if(filter[i][strlen(filter[i])-1] == '\n'){
            filter[i][strlen(filter[i])-1] = '\0'; 
        }
    }
    fclose(file);
    return filter;
}

int check_method(char* request){
    char methods[9][10]={
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"
    };
    for(int i=0;i<9;i++){
        if(strstr(request, methods[i]) != NULL){
            return 1;
        }
    }
    return 0;
}

int check_HTTP(char* request){
    char HTTP[2][10] = {
        "HTTP/1.0", "HTTP/1.1"
    };
    for(int i=0;i<2;i++){
        if(strstr(request, HTTP[i]) != NULL){
            return 1;
        }
    }
    return 0;
}

char* getHost(char* buffer){
    char* afterHost = strstr(buffer, "Host:")+6;
    char* host = (char*)malloc(sizeof(char)*strlen(buffer));
    int count=0;
    while(1){
        if(afterHost[count]=='\r' && afterHost[count+1] == '\n'){
            break;
        }
        host[count]=afterHost[count];
        count+=1;
    }
    host[count] = '\0';
    return host;
}

char* getPort(char* host){
    char* port = (char*)malloc(sizeof(char) * strlen(host));
    int portExist = 0;
    int count = 0;
    for(int i=0;i<strlen(host);i++){
        if(host[i] == ':' && i+1<strlen(host)){
            for(int j=i+1;j<strlen(host);j++){
                if(host[j]>47 && host[j]<58){
                    port[count] = host[j];
                    portExist = 1;
                    count += 1;
                }else{
                    break;
                }
            }
        }
    }
    if(portExist == 1){
        port[count] = '\0';
        return port;
    }
    strcpy(port,"80");
    return port;
}

char* getWithoutPort(char* host){
    char* host_without_port = (char*)malloc(sizeof(char)* strlen(host)+1);
    int portExisted = 0;
    int count =0;
    for(int i=0;i<strlen(host);i++){
        if(portExisted == 1){
            continue;
        }else{
            if(host[i] == ':' && i+1 < strlen(host)){
                if(host[i+1] > 47 && host[i+1] < 58){
                    portExisted = 1;
                }
            }else{
                host_without_port[count] = host[i];
                count += 1;
            }
        }
    }
    host_without_port[count] = '\0';
    return host_without_port;
}

int check_ids_in_filter(char* host, int* index){
    struct sockaddr_in saddr;
    struct hostent* hp = NULL;
    hp= gethostbyname(host);
    saddr.sin_addr.s_addr=((struct in_addr*)(hp->h_addr))->s_addr;
    char* server = (char*)malloc(sizeof(char)*20);
    char* host2 = (char*)malloc(sizeof(char)*5);
    for(int i=0;i<lines_count;i++){
        int count = 0;
        int count2=0; 
        int found = 0;
        if(index[i] == -1){
            break;
        }
        for(int j=0;j<strlen(filter[index[i]]);j++){
            if(filter[index[i]][j] == '/'){
                found = 1;
                for(int k=j+1;k<strlen(filter[index[i]]);k++){
                    host2[count] = filter[index[i]][k];
                    count +=1;
                }
                break;
            }
            server[count2] = filter[index[i]][j];
            count2 +=1;
        }
        server[count2] = '\0';
        host2[count] = '\0';
        if(found == 0){
            strcpy(host2, "32");
        }
        in_addr_t addr;
        addr = inet_addr(server);
        addr = htonl(addr);
        uint32_t buff = 0;
        int m = 0;
        for(m=31;m>=32-atoi(host2);m--){
            buff |= (1 << m);
        }
        if((buff & addr)==(buff & saddr.sin_addr.s_addr)){
            free(server);
            free(host2);
            return 1;
        }
        for(int l=0;l<count2;l++){
            server[l] = '\0';
        }
        for(int l=0;l<count;l++){
            server[l] = '\0';
        }
    }
    free(server);
    free(host2);
    return 0;
}

int check_filter(char* host){
    int index[lines_count];
    int count = 0;
    for(int i=0;i<lines_count;i++){
        if(filter[i][0] > 57 || filter[i][0] < 48){
            if(strcmp(filter[i], host)==0){
                return 1;
            }
        }
        else{
            index[count]=i;
            count += 1;
        }
    }
    index[count] = -1;
    if(check_ids_in_filter(host, index)==1){
        return 1;
    }
    return 0;
}

void* send_response(void* arg){
    int fd = *((int*)arg);
    free(arg);
    int bytes = 0;
    int bytesRead = 0;
    int bytesWritten = 0;
    char* c;
    char* buffer = (char*)malloc(sizeof(char)*1000);
    char* reader = (char*)malloc(sizeof(char)*1000);
    unsigned char* buffer2 = (unsigned char*)malloc(sizeof(unsigned char)*4000);
    unsigned char* reader2 = (unsigned char*)malloc(sizeof(unsigned char)*4000);
    char* buffer_without_encoding;
    char* port;
    char* error;
    char* host_without_port;
    char* host;
    char* closed_buffer;
    struct sockaddr_in saddr;
    int main_server_fd = -1;
    struct hostent* hp = NULL;
    strcpy(reader, "\0");
    strcpy(buffer, "\0");
    strcpy(reader2, "\0");
    strcpy(buffer2, "\0");
    while(1){
        bytes = read(fd, reader, 999);
        if(bytes < 0){
            perror("error: read\n");
            free(buffer);
            free(reader);  
            free(buffer2);
            free(reader2);  
            close(fd);
            return NULL;
        }
        reader[bytes] = '\0';
        strcat(buffer,reader);
        buffer[strlen(buffer)] = '\0';
        if((c = strstr(buffer, "\r\n\r\n")) != NULL){
            *(c+4) = '\0';
            break;
        }
        buffer = (char*)realloc(buffer, strlen(buffer)+1001);
        buffer[strlen(buffer)] = '\0';
        for(int i=0;i< 999;i++){
            reader[i]='\0';
        }
    }
    closed_buffer = closingConnection(buffer);
    if(check_HTTP(buffer) == 0 || check_method(buffer) == 0 || strstr(buffer,"Host:")==NULL){
        error = errors("400", "Bad Request");
        bytesWritten = write(fd, error, strlen(error));
        if(bytesWritten < 0){
            perror("error: write\n");
            free(buffer);
            free(closed_buffer);
            free(reader);
            free(buffer2);
            free(reader2);
            free(error);
            close(fd);
            return NULL;
        }
        free(buffer);
        free(reader);  
        free(buffer2);
        free(reader2);
        free(closed_buffer);
        free(error);
        close(fd);
        return NULL;
    }
    if(strstr(buffer, "GET") == NULL){
        error = errors("501", "Not supported");
        bytesWritten = write(fd, error, strlen(error));
        if(bytesWritten < 0){
            perror("error: write\n");
            free(buffer);
            free(reader);
            free(error);
            free(buffer2);
            free(reader2);
            free(closed_buffer);
            close(fd);
            return NULL;
        }
        free(buffer);
        free(reader);
        free(error);
        free(buffer2);
        free(closed_buffer);
        free(reader2);
        close(fd);
        return NULL;
    }
    host = getHost(buffer);
    port = getPort(host);
    host_without_port = getWithoutPort(host);
    hp= gethostbyname(host_without_port);
    if(hp == NULL){
        error = errors("404", "Not Found");
        bytesWritten = write(fd, error, strlen(error));
        if(bytesWritten < 0){
            perror("error: write\n");
            free(buffer);
            free(port);
            free(closed_buffer);
            free(host_without_port);
            free(reader);
            free(buffer2);
            free(reader2);
            free(host);
            free(error);
            close(fd);
            return NULL;
        }
        free(buffer);
        free(host);
        free(port);
        free(host_without_port);
        free(reader);
        free(buffer2);
        free(reader2);
        free(closed_buffer);
        free(error);
        close(fd);
        return NULL;
    }
    saddr.sin_family=AF_INET;
    saddr.sin_addr.s_addr=((struct in_addr*)(hp->h_addr))->s_addr;
    saddr.sin_port = htons(atoi(port));
    if(check_filter(host_without_port) == 1){
        error = errors("403", "Forbidden");
        bytesWritten = write(fd, error, strlen(error));
        if(bytesWritten < 0){
            perror("error: write\n");
            free(port);
            free(host_without_port);
            free(buffer);
            free(reader);
            free(buffer2);
            free(reader2);
            free(closed_buffer);
            free(error);
            close(fd);
            return NULL;
        }
        free(buffer);
        free(host);
        free(port);
        free(host_without_port);
        free(reader);
        free(buffer2);
        free(reader2);
        free(closed_buffer);
        free(error);
        close(fd);
        return NULL;    
    }
    buffer_without_encoding = deleteEncoding(closed_buffer);
    if((main_server_fd = socket(PF_INET, SOCK_STREAM, 0))<0){
        perror("error: socket\n");
        free(buffer);
        free(host);
        free(port);
        free(host_without_port);
        free(reader);
        free(buffer2);
        free(reader2);
        free(closed_buffer);
        free(buffer_without_encoding);
        close(fd);
        return NULL; 
    }
    if(connect(main_server_fd, (struct sockaddr*) &saddr, sizeof (saddr)) < 0){
        perror("error: connect\n");
        free(buffer);
        free(host);
        free(port);
        free(host_without_port);
        free(reader);
        free(buffer2);
        free(reader2);
        close(main_server_fd);
        close(fd);
        free(closed_buffer);
        free(buffer_without_encoding);
        return NULL;
    }
    if(write(main_server_fd, buffer_without_encoding, strlen(buffer_without_encoding)) < 0){
        error = errors("500", "Internal Sever Error");
        bytesWritten = write(fd, error, strlen(error));
        if(bytesWritten < 0){
            perror("error: write\n");
            free(port);
            free(host_without_port);
            free(buffer);
            free(reader);
            free(buffer2);
            free(reader2);
            free(error);
            close(main_server_fd);
            close(fd);
            free(closed_buffer);
            free(buffer_without_encoding);
            return NULL;
        }
        free(buffer);
        free(host);
        free(port);
        free(host_without_port);
        free(reader);
        free(buffer2);
        free(reader2);
        free(error);
        close(fd);
        free(closed_buffer);
        free(buffer_without_encoding);
        close(main_server_fd);
        return NULL;
    }
    int length = 0;
    int length2 = 4000;
    while((bytesRead = read(main_server_fd, reader2,3999))>0){
        reader2[bytesRead] = '\0';
        length += bytesRead;
        length2 += 4000;
        if(bytesRead < 0){
            error = errors("500", "Internal Sever Error");
            bytesWritten = write(fd, error, strlen(error));
            if(bytesWritten < 0){
                perror("error: write\n");
                free(port);
                free(host_without_port);
                free(buffer);
                free(reader);
                free(buffer2);
                free(reader2);
                free(closed_buffer);
                free(buffer_without_encoding);
                free(error);
                close(main_server_fd);
                close(fd);
                return NULL;
            }
            free(buffer);
            free(host);
            free(port);
            free(host_without_port);
            free(reader);
            free(buffer2);
            free(reader2);
            free(error);
            free(closed_buffer);
            free(buffer_without_encoding);
            close(fd);
            close(main_server_fd);
            return NULL;
        }
        if(bytesRead == 0){
            break;
        }
        reader2[bytesRead] = '\0';
        strcat(buffer2,reader2);
        buffer2[length] = '\0';
        buffer2 = (unsigned char*)realloc(buffer2, length2);
        buffer2[length] = '\0';
        for(int i=0;i< 4000;i++){
            reader2[i]='\0';
        }
    }
    write(fd, buffer2, strlen(buffer2));
    free(buffer);
    free(reader);
    free(buffer2);
    free(reader2);
    free(host);
    free(closed_buffer);
    free(buffer_without_encoding);
    free(port);
    free(host_without_port);
    close(fd);
    close(main_server_fd);
}

int main(int argc, char* argv[]) {
    if(argc != 5){
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(0);
    }
    if(isNum(argv[1]) == 0 || isNum(argv[2]) == 0 || isNum(argv[3]) == 0){
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(0);
    }
    int portNum = atoi(argv[1]);
    int size = atoi(argv[2]);
    int max_tasks = atoi(argv[3]);
    if(portNum <= 0 || size <= 0 || max_tasks <= 0){
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(0);
    }
    filter = readFilter(argv[4]);
    int server_fd = 0;
    if((server_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        perror("error: socket\n");
        for(int i=0;i<lines_count;i++){
            free(filter[i]);
        }
        free(filter);
        exit(0);
    }
    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(portNum);
    srv.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(server_fd, (struct sockaddr*) &srv, sizeof(srv)) < 0){
        perror("error: bind\n");
        for(int i=0;i<lines_count;i++){
            free(filter[i]);
        }
        free(filter);
        close(server_fd);
        exit(0);
    }
    if(listen(server_fd, 5) < 0){
        perror("error: listen\n");
        for(int i=0;i<lines_count;i++){
            free(filter[i]);
        }
        free(filter);
        exit(0);
    }
    int tasks_accepted = 0;
    struct sockaddr_in cli;
    int cli_len = sizeof(cli);
    threadpool* tp = create_threadpool(size); 
    if(tp == NULL){
        printf("couldnt create the threadpool\n");
        for(int i=0;i<lines_count;i++){
            free(filter[i]);
        }
        free(filter);
        close(server_fd);
        exit(0);
    }
    int bytes = 0;
    while(tasks_accepted < max_tasks){
        int* newFd = (int*)malloc(sizeof(int));
        *newFd = accept(server_fd, (struct sockaddr*) &cli, &cli_len);
        if(*newFd < 0){
            perror("“error: accept\n");
            for(int i=0;i<lines_count;i++){
                free(filter[i]);
            }
            free(filter);
            close(server_fd);
            exit(0);
        }
        tasks_accepted += 1;
        dispatch(tp, (dispatch_fn)send_response, (void*)(newFd));
    }
    close(server_fd);
    destroy_threadpool(tp);
    for(int i=0;i<lines_count;i++){
        free(filter[i]);
    }
    free(filter);
}