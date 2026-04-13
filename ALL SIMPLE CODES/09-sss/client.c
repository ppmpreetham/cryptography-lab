#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(){
    int s = connect_to(8080);

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