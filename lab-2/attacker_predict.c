#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define MODULUS 9

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

int main() {
    printf("=== ATTACK 2: TOKEN PREDICTION ATTACK ===\n");
    printf("Attacker knows φ(%d) = 6 (cycle length)\n\n", MODULUS);
    
    int user_id = 2;
    
    printf("Analyzing token cycle for User_ID = %d:\n", user_id);
    printf("Computing powers: %d^k mod %d\n\n", user_id, MODULUS);
    
    for (int k = 1; k <= 15; k++) {
        long long token = mod_exp(user_id, k, MODULUS);
        printf("k=%2d: %d^%d mod %d = %lld", k, user_id, k, MODULUS, token);
        
        if (k > 6 && token == mod_exp(user_id, k - 6, MODULUS)) {
            printf(" ← REPEATS (cycle detected)");
        }
        printf("\n");
    }
    
    printf("\n⚠ VULNERABILITY: Multiple k values produce same token!\n");
    printf("Example: k=1, k=7, k=13 all produce token=2\n");
    printf("Secret k becomes meaningless!\n\n");
    
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    
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
    
    printf("Launching Token Prediction Attack...\n");
    printf("Using predicted token (without knowing actual k)\n");
    
    long long token = mod_exp(user_id, 1, MODULUS);
    
    char message[256];
    sprintf(message, "%d %lld", user_id, token);
    send(sock, message, strlen(message), 0);
    
    printf("Sent: User_ID=%d, Token=%lld (guessed from cycle)\n", user_id, token);
    
    read(sock, buffer, 1024);
    printf("\nServer response: %s\n", buffer);
    
    if (strstr(buffer, "SUCCESS")) {
        printf("\n✓ ATTACK SUCCESSFUL!\n");
        printf("Predicted token accepted despite not knowing k!\n");
    }
    
    close(sock);
    return 0;
}