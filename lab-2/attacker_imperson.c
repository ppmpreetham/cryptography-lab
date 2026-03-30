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
    printf("=== ATTACK 3: IMPERSONATION ATTACK ===\n");
    printf("Attacker creates fake User_ID and finds valid token\n\n");
    
    int fake_user_id = 4;
    
    printf("Attacker chooses User_ID = %d\n", fake_user_id);
    printf("Computing token cycle:\n\n");
    
    for (int k = 1; k <= 6; k++) {
        long long token = mod_exp(fake_user_id, k, MODULUS);
        printf("k=%d: %d^%d mod %d = %lld\n", k, fake_user_id, k, MODULUS, token);
    }
    
    printf("\nAttacker notices: %d^3 mod %d = 1\n", fake_user_id, MODULUS);
    printf("For any k that is multiple of 3, token will be 1\n");
    printf("(Server's k=7 gives same token as k=1 in this cycle)\n\n");
    
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
    
    printf("Launching Impersonation Attack...\n");
    
    long long token = mod_exp(fake_user_id, 1, MODULUS); 
    
    char message[256];
    sprintf(message, "%d %lld", fake_user_id, token);
    send(sock, message, strlen(message), 0);
    
    printf("Sent: User_ID=%d (fake), Token=%lld\n", fake_user_id, token);
    
    read(sock, buffer, 1024);
    printf("\nServer response: %s\n", buffer);
    
    if (strstr(buffer, "SUCCESS")) {
        printf("\n✓ ATTACK SUCCESSFUL!\n");
        printf("Attacker authenticated as fake User_ID=%d!\n", fake_user_id);
        printf("System cannot distinguish legitimate from fake users!\n");
    } else {
        printf("\n✗ Attack failed with this token, trying another...\n");
    }
    
    close(sock);
    return 0;
}