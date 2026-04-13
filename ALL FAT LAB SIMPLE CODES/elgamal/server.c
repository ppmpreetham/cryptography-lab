#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>

typedef long long ll;

ll modexp(ll b,ll e,ll p){ ll r=1; while(e){ if(e&1) r=r*b%p; b=b*b%p; e>>=1; } return r; }
ll modinv(ll a,ll p){ return modexp(a,p-2,p); }
ll mulmod(ll a,ll b,ll p){ return (a*b)%p; }
ll rand_range(ll p){ return rand()%(p-2)+1; }

void keygen(ll p,ll g,ll *x,ll *y){ *x=rand_range(p); *y=modexp(g,*x,p); }
void encrypt(ll m,ll p,ll g,ll y,ll *c1,ll *c2){
    ll k=rand_range(p);
    *c1=modexp(g,k,p);
    ll yk=modexp(y,k,p);
    *c2=mulmod(m,yk,p);
}
ll decrypt(ll c1,ll c2,ll p,ll x){
    ll s=modexp(c1,x,p);
    return mulmod(c2,modinv(s,p),p);
}
void homo(ll c1a,ll c2a,ll c1b,ll c2b,ll p,ll *c1,ll *c2){
    *c1=(c1a*c1b)%p;
    *c2=(c2a*c2b)%p;
}

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) (n = read(fd, buf, 1024), buf[n]=0)
#define W_INT(fd, x) { int t=htonl(x); write(fd,&t,4); }
#define R_INT(fd, x) { int t; read(fd,&t,4); x=ntohl(t); }

int main(){
    int s=socket(2,1,0),c,n;
    struct sockaddr_in a={2,htons(8080),0};

    bind(s,(void*)&a,16);
    listen(s,5);
    c=accept(s,0,0);

    ll p=23,g=5,x,y;
    keygen(p,g,&x,&y);

    W_INT(c,p); W_INT(c,g); W_INT(c,y);

    while(1){
        // -------- NORMAL --------
        ll c1,c2;
        if(read(c,&c1,0)<=-1) break;

        R_INT(c,c1); R_INT(c,c2);
        ll m = decrypt(c1,c2,p,x);
        printf("Normal: %lld\n",m);

        // -------- HOMO --------
        ll c1a,c2a,c1b,c2b;
        R_INT(c,c1a); R_INT(c,c2a);
        R_INT(c,c1b); R_INT(c,c2b);

        ll hc1,hc2;
        homo(c1a,c2a,c1b,c2b,p,&hc1,&hc2);

        ll prod = decrypt(hc1,hc2,p,x);
        printf("Product: %lld\n",prod);
    }

    close(c); close(s);
}