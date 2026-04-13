typedef long long ll;

ll modexp(ll b,ll e,ll p){
    ll r=1;
    while(e){ if(e&1) r=r*b%p; b=b*b%p; e>>=1; }
    return r;
}

ll modinv(ll a,ll m){ return modexp(a,m-2,m); }

ll gcd(ll a,ll b){ return b?gcd(b,a%b):a; }

ll rand_range(ll p){ return rand()%(p-2)+1; }

// signature
void sign(ll m,ll p,ll g,ll x,ll *r,ll *s){
    ll k;
    do{ k = rand_range(p); } while(gcd(k,p-1)!=1);

    *r = modexp(g,k,p);
    ll kinv = modinv(k,p-1);

    *s = (kinv * (m - x*(*r)%(p-1) + (p-1))) % (p-1);
}

// verify
int verify(ll m,ll r,ll s,ll p,ll g,ll y){
    ll v1 = modexp(g,m,p);
    ll v2 = (modexp(y,r,p) * modexp(r,s,p)) % p;
    return v1 == v2;
}

// macros (ONLY THESE)
#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) (n = read(fd, buf, 1024), buf[n]=0)

#define W_INT(fd, x) { int t = htonl(x); write(fd, &t, sizeof(t)); }
#define R_INT(fd, x) { int t; read(fd, &t, sizeof(t)); x = ntohl(t); }