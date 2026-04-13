typedef long long ll;

ll modexp(ll b,ll e,ll p){
    ll r=1;
    while(e){ if(e&1) r=r*b%p; b=b*b%p; e>>=1; }
    return r;
}
ll modinv(ll a,ll p){ return modexp(a,p-2,p); }

#define W_INT(fd,x) { int t=htonl(x); write(fd,&t,4); }
#define R_INT(fd,x) { int t; read(fd,&t,4); x=ntohl(t); }

ll eval_poly(ll c[], int k, ll x, ll p) {
    ll result = 0;
    for(int i = k-1; i >= 0; i--) {   // still start from highest
        result = (result * x + c[i]) % p;
    }
    return result;
}

ll lagrange(ll x[], ll y[], int k, ll m) {
    ll result = 0;                    // P(0) mod m
    
    for(int i = 0; i < k; i++) {      // for every point
        ll num = 1;   // Numerator accumulator: will become  ∏_{j≠i} (-x[j])   mod m
        ll den = 1;   // Denominator accumulator: will become ∏_{j≠i} (x[i] - x[j])  mod m
        for(int j = 0; j < k; j++) {
            if(i == j) continue;       // Skip when j == i (product excludes the i-th term)
            num = num * (m - x[j]) % m;                    // num *= (- x[j]) mod m
            den = den * ((x[i] - x[j] + m) % m) % m;      // den *= (x[i] - x[j]) mod m
        }
        ll term = y[i] * num % m;           // term = y[i] * num  (still missing the division)
        term = term * modinv(den, m) % m;   // term = y[i] * num * (1/den) mod m
                                            // Now term exactly equals  y[i] * ℓ_i(0)  mod m
        result = (result + term) % m;       // Add this basis term to the total sum
    }
    
    return result;   // This is the final interpolated value P(0) mod m
}