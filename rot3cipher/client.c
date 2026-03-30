#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

char shift_char(char c, int k) {
    if (c >= 'a' && c <= 'z')
        return 'a' + (c - 'a' + k + 26) % 26;
    if (c >= 'A' && c <= 'Z')
        return 'A' + (c - 'A' + k + 26) % 26;
    return c;
}

void caesar(char *in, char *out, int k) {
    for (int i = 0; in[i]; i++)
        out[i] = shift_char(in[i], k);
    out[strlen(in)] = '\0';
}

int main() {
    int s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(9000),
        .sin_addr.s_addr = INADDR_ANY
    };

    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 1);

    int c = accept(s, NULL, NULL);

    char buf[256], dec[256];
    read(c, buf, sizeof(buf));

    printf("Received: %s\n", buf);
    caesar(buf, dec, -3);
    printf("Decrypted: %s\n", dec);

    close(c);
    close(s);
}
