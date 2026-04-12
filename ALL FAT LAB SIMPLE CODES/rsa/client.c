#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) {n = read(fd, buf, 1024); buf[n] = 0;}

#define W_INT(fd, msg) {int t = htonl(msg); write(fd, &t, sizeof(t));}
#define R_INT(fd, msg) {int t; read(fd, &t, sizeof(t)); msg = ntohl(t);}

int modinv(int n, int p){
    int res = 1;
    while(n * res % p != 1){
        res++;
    }
    return res;
}

int gcd(int a, int b){
    if (b == 0) return a;
    return gcd(b, a % b);
}

int totient(int n){
    int cnt = 0;
    for(int i = 1; i < n; i++){
        if (gcd(n,i) == 1){
            cnt++;
        }
    }
    return cnt;
}

// a^b mod p
int modexp(int a, int b, int p){
    if (p == 0) return -1;  
    int res = 1;
    a = a % p;
    while (b > 0){
        if (b % 2 ==1) res = (res * a ) % p;
        b = b/2;
        a = (a * a) % p;
    }
    return res;
}

int main(){
    int s = socket(2,1,0), c, n;
    struct sockaddr_in a = {2,htons(8080),0};
    int b[1024];
    connect(s, (struct sockaddr*)&a, 16);
    int e, n_val;
    R_INT(s, e);
    R_INT(s, n_val);
    
    while(1){
        int m;
        scanf("%d", &m);
        int enc = modexp(m,e,n_val);
        W_INT(s, enc);
    }
}