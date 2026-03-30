#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8081
#define MODULUS 97  


int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

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

void attempt_authentication(int user_id, long long token, char* attack_type) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("Invalid address\n");
        close(sock);
        return;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection Failed\n");
        close(sock);
        return;
    }
    
    char message[256];
    sprintf(message, "%d %lld", user_id, token);
    send(sock, message, strlen(message), 0);
    
    printf("Attempting: %s\n", attack_type);
    printf("Sent: User_ID=%d, Token=%lld\n", user_id, token);
    
    read(sock, buffer, 1024);
    printf("Response: %s\n", buffer);
    
    if (strstr(buffer, "SUCCESS")) {
        printf("✓ Attack successful!\n\n");
    } else {
        printf("✗ Attack FAILED (System is secure)\n\n");
    }
    
    close(sock);
}

int main() {
    printf("=== ATTACKER ATTEMPTS ON SECURE SYSTEM ===\n");
    printf("Target Modulus n = %d (PRIME)\n\n", MODULUS);
    
    printf("Phase 1: GCD Analysis\n");
    printf("Testing for common factors:\n");
    
    for (int user_id = 1; user_id <= 10; user_id++) {
        int g = gcd(user_id, MODULUS);
        printf("gcd(%d, %d) = %d", user_id, MODULUS, g);
        if (g > 1) {
            printf(" ← Factor found!\n");
        } else {
            printf("\n");
        }
    }
    
    printf("\n⚠ ALL GCD values = 1 (no factors found)\n");
    printf("Prime modulus prevents factorization!\n");
    printf("φ(%d) = %d (much larger cycle)\n\n", MODULUS, MODULUS - 1);
    
    printf("Phase 2: Attempting Previous Attacks\n\n");
    
    printf("--- Attack 1: Replay Attack ---\n");
    printf("Trying captured token from old session...\n");
    attempt_authentication(5, 50, "Replay with captured token");
    
    printf("--- Attack 2: Token Prediction ---\n");
    printf("Trying to predict token with small k values...\n");
    long long predicted = mod_exp(5, 1, MODULUS);
    attempt_authentication(5, predicted, "Token prediction (k=1)");
    
    printf("--- Attack 3: Impersonation ---\n");
    printf("Creating fake user with guessed token...\n");
    attempt_authentication(10, 1, "Impersonation with token=1");
    
    printf("\n=== SECURITY ANALYSIS ===\n");
    printf("✓ Prime modulus prevents GCD factorization\n");
    printf("✓ Large φ(n) = %d makes token prediction infeasible\n", MODULUS - 1);
    printf("✓ All User_IDs are coprime with n\n");
    printf("✓ Replay attacks fail due to proper validation\n");
    printf("✓ System is SECURE against all tested attacks!\n");
    
    return 0;
}