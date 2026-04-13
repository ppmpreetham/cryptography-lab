#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define PORT 9091
#define SECRET_KEY 42
#define SESSION_KEY 99
#define APP_PORT 9092

int main(){
    int s=create_server(PORT),c;

    while(1){
        c=accept_client(s);

        char id[64];
        R(c,id);

        xor_encrypt(id,strlen(id),SECRET_KEY); // decode

        char tgt[128];
        sprintf(tgt,"%d|%s|%ld",SESSION_KEY,id,time(0));

        xor_encrypt(tgt,strlen(tgt),SECRET_KEY);

        W(c,tgt);
        W_INT(c,APP_PORT);
        W_INT(c,SESSION_KEY);

        close(c);
    }
}