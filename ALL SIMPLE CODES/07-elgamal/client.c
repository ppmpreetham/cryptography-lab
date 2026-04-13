#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

typedef long long ll;

ll modexp(ll b,ll e,ll p){ ll r=1; while(e){ if(e&1) r=r*b%p; b=b*b%p; e>>=1; } return r; }
ll mulmod(ll a,ll b,ll p){ return (a*b)%p; }
ll rand_range(ll p){ return rand()%(p-2)+1; }

void encrypt(ll m,ll p,ll g,ll y,ll *c1,ll *c2){
    ll k=rand_range(p);
    *c1=modexp(g,k,p);
    ll yk=modexp(y,k,p);
    *c2=mulmod(m,yk,p);
}

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) (n = read(fd, buf, 1024), buf[n]=0)
#define W_INT(fd, x) { int t=htonl(x); write(fd,&t,4); }
#define R_INT(fd, x) { int t; read(fd,&t,4); x=ntohl(t); }

int main(){
    int s=socket(2,1,0),n;
    struct sockaddr_in a={2,htons(8080),inet_addr("127.0.0.1")};

    connect(s,(void*)&a,16);

    ll p,g,y;
    R_INT(s,p); R_INT(s,g); R_INT(s,y);

    while(1){
        // NORMAL
        ll m,c1,c2;
        printf("m: ");
        scanf("%lld",&m);

        encrypt(m,p,g,y,&c1,&c2);
        W_INT(s,c1); W_INT(s,c2);

        // HOMO
        ll m1,m2,c1a,c2a,c1b,c2b;
        printf("m1 m2: ");
        scanf("%lld %lld",&m1,&m2);

        encrypt(m1,p,g,y,&c1a,&c2a);
        encrypt(m2,p,g,y,&c1b,&c2b);

        W_INT(s,c1a); W_INT(s,c2a);
        W_INT(s,c1b); W_INT(s,c2b);
    }

    close(s);
}