#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    int s = connect_to(8080);

    ll user = 2;
    ll token = modexp(user,7,9);

    W_INT(s, user);
    W_INT(s, token);
}