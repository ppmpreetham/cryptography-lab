#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#define PORT 8080
#define N 3   // clients
#define K 2   // threshold

int main(){
    int s=socket(2,1,0), c[N];
    struct sockaddr_in a={2,htons(PORT),0};
    bind(s,(void*)&a,16); listen(s,N);


    for(int i=0;i<N;i++) c[i]=accept(s,0,0);

    ll p=97;
    ll secret=45;

    // polynomial coeffs: c0=secret
    ll coeffs[K];
    coeffs[0]=secret;
    for(int i=1;i<K;i++) coeffs[i]=rand()%p;

    // send shares
    for(int i=0;i<N;i++){
        ll x=i+1;
        ll y=eval_poly(coeffs,K,x,p);

        W_INT(c[i],x);
        W_INT(c[i],y);
    }

    // receive k shares back
    ll xs[K], ys[K];
    for(int i=0;i<K;i++){
        R_INT(c[i],xs[i]);
        R_INT(c[i],ys[i]);
    }

    ll rec = lagrange(xs,ys,K,p);
    printf("Reconstructed: %lld\n",rec);

    for(int i=0;i<N;i++) close(c[i]);
    close(s);
}