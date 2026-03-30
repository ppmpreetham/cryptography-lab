#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8081
#define MODULUS 97  
#define SECRET_K 23

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

int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int main() {
    int server_fd, client_sock;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("=== SECURE AUTHENTICATION SERVER ===\n");
    printf("Modulus n = %d (PRIME - SECURE!)\n", MODULUS);
    printf("Secret k = %d\n", SECRET_K);
    printf("φ(%d) = %d (large cycle length)\n", MODULUS, MODULUS - 1);
    printf("Server listening on port %d...\n\n", PORT);
    
    while (1) {
        if ((client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }
        
        
        read(client_sock, buffer, 1024);
        
        int user_id;
        long long token;
        sscanf(buffer, "%d %lld", &user_id, &token);
        
        printf("\n--- Authentication Request ---\n");
        printf("User_ID received: %d\n", user_id);
        printf("Token received: %lld\n", token);
        
        int g = gcd(user_id, MODULUS);
        printf("GCD(%d, %d) = %d ", user_id, MODULUS, g);
        
        if (g != 1) {
            printf("← NOT COPRIME! REJECTED\n");
            char response[256];
            sprintf(response, "FAILED: User_ID must be coprime with modulus");
            send(client_sock, response, strlen(response), 0);
            close(client_sock);
            continue;
        }
        printf("← Coprime verified ✓\n");
        
        long long expected_token = mod_exp(user_id, SECRET_K, MODULUS);
        printf("Expected token: %lld\n", expected_token);
        
        char response[256];
        if (token == expected_token) {
            printf("Result: ✓ AUTHENTICATION SUCCESS\n");
            sprintf(response, "SUCCESS: Authentication approved for User_ID=%d", user_id);
        } else {
            printf("Result: ✗ AUTHENTICATION FAILED\n");
            sprintf(response, "FAILED: Invalid token for User_ID=%d", user_id);
        }
        
        send(client_sock, response, strlen(response), 0);
        close(client_sock);
    }
    
    return 0;
}