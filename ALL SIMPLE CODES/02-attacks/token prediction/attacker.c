#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    ll user = 4;
    ll n = 9;

    printf("Cycle:\n");
    for(int k=1;k<=12;k++){
        printf("%lld^%d mod 9 = %lld\n",
            user, k, modexp(user,k,n));
    }

    // pick any repeating value (like k=1 or 7)
    int s = connect_to(8080);
    W_INT(s, user);
    W_INT(s, modexp(user,1,n)); // guessed token
}