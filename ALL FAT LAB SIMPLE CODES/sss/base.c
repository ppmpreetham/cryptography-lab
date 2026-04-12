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

ll lagrange(ll x[],ll y[],int k,ll p){
    ll s=0;
    for(int i=0;i<k;i++){
        ll num=1,den=1;
        for(int j=0;j<k;j++){
            if(i==j) continue;
            num=num*(p-x[j])%p;
            den=den*(x[i]-x[j]+p)%p;
        }
        ll t=y[i];
        t=t*num%p;
        t=t*modinv(den,p)%p;
        s=(s+t)%p;
    }
    return (s+p)%p;
}