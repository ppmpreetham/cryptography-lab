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

// ax+by = gcd(a,b)
// if b = 0, <--
// then:
// x = 1 <--
// y = 0 <--
// very similar to gcd
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

// ax = 1 mod(m)
ll modinv(ll a, ll m){
    ll x,y;
    ll g = egcd(a, m, &x, &y);
    if (g!=1) return -1; // sentinels of pharloom
    return (x % m + m) % m; // you prolly see this everywhere by now bro, if you dont youll hate negs coming up in your code 
}

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

// 7 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// elgamal enc, dec & homomorphic

// random in [1, p-2]
ll rand_range(ll p) {
    return rand() % (p - 2) + 1;
}

// key-gen
void keygen(ll p, ll g, ll *x, ll *y) {
    *x = rand_range(p);
    *y = modexp(g, *x, p);
}

// enc
void encrypt(ll m, ll p, ll g, ll y, ll *c1, ll *c2) {
    ll k = rand_range(p);

    *c1 = modexp(g, k, p);
    ll yk = modexp(y, k, p);

    *c2 = mulmod(m, yk, p);
}

// dec
ll decrypt(ll c1, ll c2, ll p, ll x) {
    ll s = modexp(c1, x, p);
    ll s_inv = modinv(s, p);

    return mulmod(c2, s_inv, p);
}

// homomorphic mult
void homo(ll c1a, ll c2a, ll c1b, ll c2b,
          ll p, ll *c1, ll *c2) {

    *c1 = mulmod(c1a, c1b, p);
    *c2 = mulmod(c2a, c2b, p);
}

ll eval_poly(ll coeffs[], int k, ll x, ll mod); // TODO
ll lagrange(ll x[], ll y[], int k, ll mod); // TODO
char shift_char(char c, int k);  // Caesar