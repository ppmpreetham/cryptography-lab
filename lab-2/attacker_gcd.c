#include <stdio.h>
#include <stdlib.h>

#define MODULUS 9

int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int euler_totient(int n) {
    int result = 0;
    for (int i = 1; i < n; i++) {
        if (gcd(i, n) == 1)
            result++;
    }
    return result;
}

int main() {
    printf("=== ATTACKER: GCD ANALYSIS ATTACK ===\n");
    printf("Target System Modulus n = %d\n\n", MODULUS);
    
    printf("Phase 1: Passive Traffic Sniffing\n");
    printf("Attacker captured from network:\n");
    printf("  - Modulus n = %d (PUBLIC)\n", MODULUS);
    printf("  - Various User_IDs and Tokens\n\n");
    
    printf("Phase 2: GCD Analysis\n");
    printf("Testing different User_IDs for common factors with n:\n\n");
    
    int vulnerable_found = 0;
    
    for (int user_id = 1; user_id <= 10; user_id++) {
        int g = gcd(user_id, MODULUS);
        printf("User_ID = %d: gcd(%d, %d) = %d", user_id, user_id, MODULUS, g);
        
        if (g > 1) {
            printf(" ← VULNERABILITY DETECTED!\n");
            vulnerable_found = 1;
            
            printf("  → Factor discovered: %d\n", g);
            printf("  → Factorization: %d = %d × %d\n", MODULUS, g, MODULUS/g);
        } else {
            printf(" (safe for this user)\n");
        }
    }
    
    if (vulnerable_found) {
        printf("\n⚠ SYSTEM COMPROMISED!\n");
        printf("Prime factorization of n achieved\n");
        
        int phi = euler_totient(MODULUS);
        printf("φ(%d) = %d\n", MODULUS, phi);
        
        printf("\nWith φ(n) known, attacker can:\n");
        printf("1. Predict token cycles\n");
        printf("2. Compute multiple valid tokens\n");
        printf("3. Launch replay attacks\n");
        printf("4. Impersonate other users\n");
    }
    
    return 0;
}