#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    int s = connect_to(8080);

    ll fake_user = 4;

    // exploit cycle: 4^k mod 9 : {4,7,1}
    ll fake_token = 4; // valid cycle value

    W_INT(s, fake_user);
    W_INT(s, fake_token);
}