typedef long long ll; // dont you hate typing long long names?

// base^exp mod p
ll modexp(ll base, ll exp, ll p) {
    ll result = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % p;
        }
        base = (base * base) % p;
        exp = exp / 2;
    }
    return result;
}

ll gcd(ll a, ll b){
    if (b == 0) return a;
    return gcd(b, a%b);
}

// total numbers that are cofactors to & till that number
ll totient(ll n){
    ll res = 0;
    for (int i = 0; i<n; i++){
        if (gcd(i,n)==1){
            res++ ;
        }
    }
    return res;
}

ll egcd(ll a, ll b, ll *x, ll *y){
    if (b==0){
        *x = 1;
        *y = 0;
        return a;
    }
    ll x1, y1;
    ll d = egcd(b, a%b, &x1, &y1);
    *x = y1;
    *y = x1 - y1*(a/b);
    return d;
}

ll modinv(ll a, ll m){
    ll x,y;
    ll g = egcd(a, m, &x, &y);
    if (g!=1) return -1; // sentinels of pharloom
    return (x % m + m) % m; // you prolly see this everywhere by now bro, if you dont youll hate negs coming up in your code 
}