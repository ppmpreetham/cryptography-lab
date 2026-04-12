#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
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
    bind(s, (struct sockaddr*)&a, 16);
    listen(s, 5);
    printf("[SERVER] Waiting for connection...\n"); fflush(stdout);
    c = accept(s, 0, 0);
    printf("[SERVER] Client connected\n"); fflush(stdout);
    
    int p = 3, q = 11;
    int n_val = p*q;
    int tot = totient(n_val);
    int e = 7;
    printf("[SERVER] p=%d q=%d n=%d tot=%d e=%d\n", p, q, n_val, tot, e); fflush(stdout);
    
    if (gcd(e, tot) != 1) printf("[SERVER] ERROR: bad e\n");
    
    int d = modinv(e, tot);
    printf("[SERVER] d=%d\n", d); fflush(stdout);
    
    printf("[SERVER] Sending e=%d n=%d\n", e, n_val); fflush(stdout);
    W_INT(c, e);
    W_INT(c, n_val);
    printf("[SERVER] Sent. Entering receive loop...\n"); fflush(stdout);
    
    while(1){
        int enc;
        printf("[SERVER] Waiting for encrypted value...\n"); fflush(stdout);
        int r = read(c, &enc, sizeof(enc));
        printf("[SERVER] read() returned %d bytes\n", r); fflush(stdout);
        if(r <= 0){ printf("[SERVER] Connection closed or error\n"); fflush(stdout); break; }
        enc = ntohl(enc);
        printf("[SERVER] Received enc=%d\n", enc); fflush(stdout);
        int dec = modexp(enc, d, n_val);
        printf("[SERVER] Decrypted: %d\n", dec); fflush(stdout);
    }
}