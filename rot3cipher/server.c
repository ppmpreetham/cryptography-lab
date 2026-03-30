#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

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
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(9000),
        .sin_addr.s_addr = inet_addr("127.0.0.1")
    };

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    char msg[] = "attack at dawn";
    printf("%s", msg);
    char enc[256];

    caesar(msg, enc, +3);
    write(sock, enc, strlen(enc));

    close(sock);
}
