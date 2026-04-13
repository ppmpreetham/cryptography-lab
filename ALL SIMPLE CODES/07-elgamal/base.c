typedef long long ll;

ll modexp(ll b,ll e,ll p){
    ll r=1;
    while(e){ if(e&1) r=r*b%p; b=b*b%p; e>>=1; }
    return r;
}

ll modinv(ll a,ll p){ return modexp(a,p-2,p); }
ll mulmod(ll a,ll b,ll p){ return (a*b)%p; }

ll rand_range(ll p){ return rand()%(p-2)+1; }

void keygen(ll p,ll g,ll *x,ll *y){
    *x = rand_range(p);
    *y = modexp(g,*x,p);
}

void encrypt(ll m,ll p,ll g,ll y,ll *c1,ll *c2){
    ll k = rand_range(p);
    *c1 = modexp(g,k,p);
    ll yk = modexp(y,k,p);
    *c2 = mulmod(m,yk,p);
}

ll decrypt(ll c1,ll c2,ll p,ll x){
    ll s = modexp(c1,x,p);
    ll inv = modinv(s,p);
    return mulmod(c2,inv,p);
}

void homo(ll c1a,ll c2a,ll c1b,ll c2b,ll p,ll *c1,ll *c2){
    *c1 = (c1a*c1b)%p;
    *c2 = (c2a*c2b)%p;
}

#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) (n = read(fd, buf, 1024), buf[n]=0)

#define W_INT(fd, x) { int t = htonl(x); write(fd, &t, sizeof(t)); }
#define R_INT(fd, x) { int t; read(fd, &t, sizeof(t)); x = ntohl(t); }