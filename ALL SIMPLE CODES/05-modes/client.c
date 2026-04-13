#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, msg) {last = read(fd, msg, 1024); buf[last] = 0;}

int main(){
    int s = socket(2,1,0), last;
    struct sockaddr_in a = {2, htons(8080), 0};
    int buf[1024];
    connect(s, (struct sockaddr*)&a, 16);

    return close(s);
}