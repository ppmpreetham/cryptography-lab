#define W(fd, msg) write(fd, msg, strlen(msg))
#define R(fd, buf) (n = read(fd, buf, 1024), buf[n]=0)

#define W_INT(fd, x) { int t = htonl(x); write(fd, &t, sizeof(t)); }
#define R_INT(fd, x) { int t; read(fd, &t, sizeof(t)); x = ntohl(t); }

void xor_encrypt(char *d,int n,int k){
    for(int i=0;i<n;i++) d[i]^=k;
}

int connect_to(int port){
    int s = socket(2,1,0);
    struct sockaddr_in a = {2, htons(port), inet_addr("127.0.0.1")};
    connect(s,(void*)&a,sizeof(a));
    return s;
}

int create_server(int port){
    int s = socket(2,1,0);
    struct sockaddr_in a = {2, htons(port), 0};
    bind(s,(void*)&a,sizeof(a));
    listen(s,5);
    return s;
}

int accept_client(int s){
    return accept(s,0,0);
}