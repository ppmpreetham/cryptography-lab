#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define MODULUS 9
#define SECRET_K 7

long long mod_exp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

int main(int argc, char *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    
    if (argc != 2) {
        printf("Usage: %s <User_ID>\n", argv[0]);
        return -1;
    }
    
    int user_id = atoi(argv[1]);
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\nSocket creation error\n");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address\n");
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed\n");
        return -1;
    }
    
    printf("=== LEGITIMATE CLIENT ===\n");
    printf("User_ID: %d\n", user_id);
    
    long long token = mod_exp(user_id, SECRET_K, MODULUS);
    
    printf("Computing token: %d^%d mod %d = %lld\n", user_id, SECRET_K, MODULUS, token);
    
    char message[256];
    sprintf(message, "%d %lld", user_id, token);
    send(sock, message, strlen(message), 0);
    printf("Sent to server: User_ID=%d, Token=%lld\n", user_id, token);
    
    read(sock, buffer, 1024);
    printf("\nServer response: %s\n", buffer);
    
    close(sock);
    return 0;
}