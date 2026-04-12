#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#define W(fd, msg) write(fd, msg, strlen(msg));
#define R(fd, msg) {last = read(fd, msg, 1024); msg[last] = 0;}

void ceasar_decrypt(char *s, int key){
    for(int i = 0; s[i] != '\0'; i++){
        char ch = s[i];
        if (islower(ch)){
            s[i] = (ch - 'a' - key + 26) % 26 + 'a';
        } else if (isupper(ch)){
            s[i] = (ch - 'A' - key + 26) % 26 + 'A';
        }
    }
}

void ceasar_encrypt(char *s, int key){
    for(int i = 0; s[i] != '\0'; i++){
        char ch = s[i];
        if (islower(ch)){
            s[i] = (ch - 'a' + key) % 26 + 'a';
        } else if (isupper(ch)){
            s[i] = (ch - 'A' + key) % 26 + 'A';
        }
    }
}

int main(){
    int s = socket(2,1,0), c , last;
    struct sockaddr_in a = {2,htons(8080),0};
    bind(s, (struct sockaddr*)&a, 16);
    listen(s, 5);
    c = accept(s,0,0);

    while (1){
        char n[1024];
        R(c, n);
        printf("Client sent: %s", n);
        printf("With hard difficulty in decrypting:\n");
        for(int i = 0; i < 26; i++){
            ceasar_decrypt(n, i);
            printf("Key %d: %s",i, n);

        }
    }

    return close(s) + close(c);
}