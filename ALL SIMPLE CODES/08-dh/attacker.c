// MALLORY(m1,m2)
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
    int s1 = create_server(8081);
    int bob = accept_client(s1);
    int alice = connect_to(8080);

    ll p = 23, g = 5;
    ll m1 = 3, m2 = 7;
    
    ll M1 = modexp(g, m1, p); //alice
    ll M2 = modexp(g, m2, p); //bob

    // time for bob has come
    ll B;
    R_INT(bob, B);

    W_INT(bob, M1);
    ll bobs_secret = modexp(B,m1, p);
    printf("BOB: %d\n", bobs_secret);
    
    // time for alice has come
    W_INT(alice, M2);
    
    ll A;
    R_INT(alice, A);
    ll alices_secret = modexp(A, m2, p);
    printf("ALICE: %d\n", alices_secret);

    
}