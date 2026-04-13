#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    int s=socket(2,1,0),n;
    struct sockaddr_in a={2,htons(8080),inet_addr("127.0.0.1")};

    connect(s,(void*)&a,16);

    ll p,g,y;
    R_INT(s,p); R_INT(s,g); R_INT(s,y);

    // client private key (for signing)
    ll x = rand_range(p);

    while(1){
        ll m,r,sig;

        printf("m: ");
        scanf("%lld",&m);

        sign(m,p,g,x,&r,&sig);

        // send message + signature
        W_INT(s,m);
        W_INT(s,r);
        W_INT(s,sig);
    }

    close(s);
}