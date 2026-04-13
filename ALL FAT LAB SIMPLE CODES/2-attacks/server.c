#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>

int main(){
    int s = create_server(8080);
    int c = accept_client(s);

    ll n = 9, k = 7;

    ll user, token;
    R_INT(c, user);
    R_INT(c, token);

    ll expected = modexp(user, k, n);

    if(token == expected)
        printf("SUCCESS\n");
    else
        printf("FAIL\n");
}