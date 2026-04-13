#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    int s = connect_to(8080);

    // captured earlier
    ll user = 2;
    ll token = 2;

    W_INT(s, user);
    W_INT(s, token);
}