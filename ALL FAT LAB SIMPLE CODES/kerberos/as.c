#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define PORT 9092
#define SECRET_KEY 42

int main(){
    int s=create_server(PORT),c;

    while(1){
        c=accept_client(s);

        char tgt[128], msg[128];
        int sk; char id[64]; long ts;

        R(c,tgt);
        xor_encrypt(tgt,strlen(tgt),SECRET_KEY);

        sscanf(tgt,"%d|%[^|]|%ld",&sk,id,&ts);

        if(strcmp(id,"alice")!=0){
            W(c,"TGT_INVALID");
            close(c);
            continue;
        }

        R(c,msg);
        xor_encrypt(msg,strlen(msg),sk);

        printf("User: %s\n",id);
        printf("Msg: %s\n",msg);

        char res[]="HELLO WORLD";
        xor_encrypt(res,strlen(res),sk);
        W(c,res);

        close(c);
    }
}