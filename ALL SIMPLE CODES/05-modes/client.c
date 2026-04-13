#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, msg) {last = read(fd, msg, 1024); buf[last] = 0;}

typedef long long ll;

int connect_to(int port){
    int s = socket(2,1,0);
    struct sockaddr_in a = {2, htons(port), 0};
    connect(s,(void*)&a,sizeof(a));
    return s;
}

int main(){
    int s = connect_to(8080);

    uint8_t pt[8] = "HELLO123";
    uint8_t ct[8], out[8];

    uint8_t iv, nonce;
    uint16_t key;

    write(s, pt, 8);

    read(s, &iv, 1);
    read(s, &nonce, 1);
    read(s, &key, 2);

    // ECB
    read(s, ct, 8);
    ecb_decrypt(ct, out, 8, key);
    printf("ECB: %s\n", out);

    // CBC
    read(s, ct, 8);
    cbc_decrypt(ct, out, 8, iv, key);
    printf("CBC: %s\n", out);

    // CFB
    read(s, ct, 8);
    cfb_decrypt(ct, out, 8, iv, key);
    printf("CFB: %s\n", out);

    // OFB
    read(s, ct, 8);
    ofb_crypt(ct, out, 8, iv, key);
    printf("OFB: %s\n", out);

    // CTR
    read(s, ct, 8);
    ctr_crypt(ct, out, 8, nonce, key);
    printf("CTR: %s\n", out);

    close(s);
}