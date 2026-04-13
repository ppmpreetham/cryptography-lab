// BOB(b)
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, msg) {last = read(fd, msg, 1024); buf[last] = 0;}

#define W_INT(fd, x) {int t = htonl(x); write(fd, &t, sizeof(t));}
#define R_INT(fd, x) {int t; read(fd, &t, sizeof(t)); x = ntohl(t);}

typedef long long ll;
ll modexp(ll b,ll e,ll p){ll r=1;b%=p;while(e){if(e&1)r=r*b%p;b=b*b%p;e>>=1;}return r;}

int connect_to(int port){
    int s = socket(2,1,0);
    struct sockaddr_in a = {2, htons(port), 0};
    connect(s,(void*)&a,sizeof(a));
    return s;
}

int create_server(int port){
    int s = socket(2,1,0);
    struct sockaddr_in a = {2, htons(port), 0};
    bind(s,(void*)&a,sizeof(a));
    listen(s,5);
    return s;
}

int accept_client(int s){
    return accept(s,0,0);
}

int main(){
    int s = connect_to(8081);

    ll p=23, g=5;
    ll b = 4;

    ll B = modexp(g,b,p);
    W_INT(s , B);

    ll M1;
    R_INT(s, M1);
    ll k_b = modexp(M1, b, p);
    printf("%d", k_b); 
}