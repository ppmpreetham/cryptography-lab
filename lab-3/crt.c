long long egcd(long long a, long long b, long long *x, long long *y) {
    if (b == 0) {
        *x = 1; *y = 0;
        return a;
    }
    long long x1, y1;
    long long g = egcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

long long modInverse(long long a, long long m) {
    long long x, y;
    long long g = egcd(a, m, &x, &y);
    if (g != 1) return -1;
    return (x % m + m) % m;
}

long long crt(long long a[], long long m[], int n) {
    long long M = 1;
    for (int i = 0; i < n; i++) M *= m[i];

    long long result = 0;

    for (int i = 0; i < n; i++) {
        long long Mi = (M / m[i]) % M;
        long long inv = modInverse(Mi, m[i]) % M;
        result = (result + a[i] * Mi * inv) % M;
    }

    return (result + M) % M;
}

long long a[] = {2,3,2};
long long m[] = {3,5,7};

int main(){
    printf("%lld\n", crt(a, m, 3)); // 23
}