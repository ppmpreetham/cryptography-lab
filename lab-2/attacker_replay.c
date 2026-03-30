#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    
    printf("=== ATTACK 1: REPLAY ATTACK ===\n");
    printf("Attacker intercepted previous communication:\n");
    printf("  Captured User_ID: 2\n");
    printf("  Captured Token: 2\n\n");
    
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
    
    printf("Launching Replay Attack...\n");
    printf("Sending captured credentials without knowing secret k\n");
    
    int user_id = 2;
    int token = 2;
    
    char message[256];
    sprintf(message, "%d %d", user_id, token);
    send(sock, message, strlen(message), 0);
    
    printf("Replayed: User_ID=%d, Token=%d\n", user_id, token);
    
    read(sock, buffer, 1024);
    printf("\nServer response: %s\n", buffer);
    
    if (strstr(buffer, "SUCCESS")) {
        printf("\n✓ ATTACK SUCCESSFUL!\n");
        printf("Attacker authenticated as User_ID=%d without knowing k!\n", user_id);
    } else {
        printf("\n✗ Attack failed\n");
    }
    
    close(sock);
    return 0;
}