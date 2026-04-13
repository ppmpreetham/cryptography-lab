#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, msg) {last = read(fd, msg, 1024); buf[last] = 0;}

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
    int s = create_server(8080);
    int c = accept_client(s);

    uint8_t pt[8], ct[8];

    read(c, pt, 8);

    uint8_t iv = 5;
    uint8_t nonce = 9;
    uint16_t key = 123;

    write(c, &iv, 1);
    write(c, &nonce, 1);
    write(c, &key, 2);

    // ECB
    ecb_encrypt(pt, ct, 8, key);
    write(c, ct, 8);

    // CBC
    cbc_encrypt(pt, ct, 8, iv, key);
    write(c, ct, 8);

    // CFB
    cfb_encrypt(pt, ct, 8, iv, key);
    write(c, ct, 8);

    // OFB
    ofb_crypt(pt, ct, 8, iv, key);
    write(c, ct, 8);

    // CTR
    ctr_crypt(pt, ct, 8, nonce, key);
    write(c, ct, 8);

    close(c);
    close(s);
}