#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) (n = read(fd, buf, 1024), buf[n]=0)

#define W_INT(fd, x) { int t = htonl(x); write(fd, &t, sizeof(t)); }
#define R_INT(fd, x) { int t; read(fd, &t, sizeof(t)); x = ntohl(t); }

#define W_STR(fd, s) { int l = strlen(s), t = htonl(l); write(fd, &t, 4); write(fd, s, l); }
#define R_STR(fd, b) { int l, t; read(fd, &t, 4); l = ntohl(t); read(fd, b, l); b[l] = 0; }

int main(){
    int s = socket(2,1,0), n;
    struct sockaddr_in a = {2, htons(8080), inet_addr("127.0.0.1")};
    char b[1024];

    connect(s, (struct sockaddr*)&a, 16);

    while (1) {
        R(s, b);
        if (n <= 0) break;
        write(1, b, strlen(b));   // print server msg
        fgets(b, 1024, stdin);    // user input
        W(s, b);
    }

    return close(s);
}