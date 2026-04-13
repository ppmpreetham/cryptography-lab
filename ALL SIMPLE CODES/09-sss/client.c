#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(){
    int s=socket(2,1,0);
    struct sockaddr_in a={2,htons(8080),inet_addr("127.0.0.1")};

    connect(s,(void*)&a,16);

    ll x,y;

    // receive share
    R_INT(s,x);
    R_INT(s,y);

    printf("Share: (%lld,%lld)\n",x,y);

    // send back to simulate participation
    W_INT(s,x);
    W_INT(s,y);

    close(s);
}