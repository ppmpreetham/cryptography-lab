#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    int s=socket(2,1,0),c,n;
    struct sockaddr_in a={2,htons(8080),0};

    bind(s,(void*)&a,16);
    listen(s,5);
    c=accept(s,0,0);

    ll p=23,g=5;
    ll x = rand_range(p);     // private
    ll y = modexp(g,x,p);     // public

    // send public key
    W_INT(c,p); W_INT(c,g); W_INT(c,y);

    while(1){
        ll m,r,sig;

        // receive message + signature
        R_INT(c,m);
        R_INT(c,r);
        R_INT(c,sig);

        int ok = verify(m,r,sig,p,g,y);

        if(ok) printf("VALID\n");
        else   printf("INVALID\n");
    }

    close(c); close(s);
}