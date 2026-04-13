#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define TGS_PORT 9091
#define SECRET_KEY 42

int main(){
    while(1){
        char id[64]; printf("user: "); scanf("%s",id);
        xor_encrypt(id,strlen(id),SECRET_KEY);

        int s=connect_to(TGS_PORT);
        W(s,id);

        char tgt[128];
        int app_port, sk;

        R(s,tgt);
        R_INT(s,app_port);
        R_INT(s,sk);
        close(s);

        int s2=connect_to(app_port);

        W(s2,tgt);

        char msg[128]; printf("msg: "); scanf("%s",msg);
        xor_encrypt(msg,strlen(msg),sk);
        
        W(s2,msg);

        char res[128];
        R(s2,res);

        if(strcmp(res,"TGT_INVALID")==0){
            printf("Invalid TGT\n");
            close(s2);
            continue;
        }

        xor_encrypt(res,strlen(res),sk);
        printf("Response: %s\n",res);

        close(s2);
    }
}