#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h> 

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

// qsort function


typedef struct {
    int shift;
    double H;
    char text[256];
} Guess;

double entropy(char *s) {
    int freq[256] = {0}, len = 0;
    for (int i = 0; s[i]; i++)
        freq[(unsigned char)s[i]]++, len++;

    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / len;
        H -= p * log2(p);
    }
    return H;
}

int cmp(const void *a, const void *b) {
    double d = ((Guess*)a)->H - ((Guess*)b)->H;
    return (d > 0) - (d < 0);
}

int main() {
    char intercepted[] = "dwwdfn dw gdzq";
    Guess g[26];

    for (int k = 0; k < 26; k++) {
        caesar(intercepted, g[k].text, -k);
        g[k].shift = k;
        g[k].H = entropy(g[k].text);
    }

    qsort(g, 26, sizeof(Guess), cmp);

    for (int i = 0; i < 26; i++)
        printf("shift=%2d  H=%.3f  %s\n", g[i].shift, g[i].H, g[i].text);
}
