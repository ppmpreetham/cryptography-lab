#include <stdio.h>
typedef long long ll;

int check(ll a, ll d, ll n){
    ll x = modexp(a, d, n);

    if(x == 1 || x == n-1) return 1;

    while(d != n-1){
        x = (x * x) % n;
        d *= 2;

        if(x == 1) return 0;
        if(x == n-1) return 1;
    }
    return 0;
}

// miller rabin
int isPrime(ll n){
    if(n < 2) return 0;
    if(n == 2 || n == 3) return 1;
    if(n % 2 == 0) return 0;

    // write n-1 = d * 2^r
    ll d = n-1;
    while(d % 2 == 0) d /= 2;

    // test multiple bases
    for(int i=0; i<5; i++){
        ll a = 2 + rand() % (n-4);
        if(!check(a, d, n))
            return 0; // composite
    }
    return 1; // probably prime
}

int main(){
    srand(time(0));

    ll n;
    printf("Enter number: ");
    scanf("%lld", &n);

    if(isPrime(n))
        printf("Probably Prime\n");
    else
        printf("Composite\n");
}