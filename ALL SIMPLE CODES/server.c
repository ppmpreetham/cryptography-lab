#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) (n = read(fd, buf, 1024), buf[n]=0)

#define W_INT(fd, x) { int t = htonl(x); write(fd, &t, sizeof(t)); }
#define R_INT(fd, x) { int t; read(fd, &t, sizeof(t)); x = ntohl(t); }


int main(){
    int s = socket(2,1,0), c, n;
    struct sockaddr_in a = {2, htons(8080), 0};
    char b[1024];

    bind(s, (struct sockaddr*)&a, 16);
    listen(s, 5);
    c = accept(s, 0, 0);

    W(c, "Enter name: ");
    R(c, b);
    printf("Name: %s\n", b);

    W(c, "Enter age: ");
    R(c, b);
    printf("Age: %s\n", b);

    W(c, "Done.\n");

    return close(c) + close(s);
}