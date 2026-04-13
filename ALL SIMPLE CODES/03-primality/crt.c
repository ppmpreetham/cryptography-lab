#include <stdio.h>

ll crt(ll *r, ll *m, int k) {
    ll M = 1;
    for (int i = 0; i < k; i++) M *= m[i];

    ll result = 0;
    for (int i = 0; i < k; i++) {
        ll Mi = M / m[i];
        ll Zi = modinv(Mi, m[i]);
        
        ll term = (r[i] * (Mi % M)) % M;
        term = (term * (Zi % M)) % M;
        
        result = (result + term) % M;
    }
    return (result + M) % M;
}

// TODO
bool miller_rabin(ll n);