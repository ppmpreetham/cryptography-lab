#define W_INT(fd,x) {int t=htonl(x); write(fd,&t,4);}
#define R_INT(fd,x) {int t; read(fd,&t,4); x=ntohl(t);}

typedef long long ll;

ll modexp(ll b,ll e,ll p){
    ll r=1; b%=p;
    while(e){ if(e&1) r=r*b%p; b=b*b%p; e>>=1; }
    return r;
}

int connect_to(int p){
    int s=socket(2,1,0);
    struct sockaddr_in a={2,htons(p),0};
    connect(s,(void*)&a,sizeof(a));
    return s;
}

int create_server(int p){
    int s=socket(2,1,0);
    struct sockaddr_in a={2,htons(p),0};
    bind(s,(void*)&a,sizeof(a));
    listen(s,5);
    return s;
}

int accept_client(int s){
    return accept(s,0,0);
}