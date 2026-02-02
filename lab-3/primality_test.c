#include <stdio.h>
#include <math.h>
#include <time.h>

typedef unsigned long long ull;

int is_prime_trial(ull n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if (n % 2 == 0) return 0;

    ull limit = (ull)sqrt((long double)n);

    for (ull i = 3; i <= limit; i += 2) {
        if (n % i == 0)
            return 0;
    }
    return 1;
}

ull power_mod(ull a, ull d, ull n) {
    ull result = 1;
    a %= n;

    while (d > 0) {
        if (d & 1) result = (result * a) % n;
        a = (a * a) % n;
        d >>= 1;
    }
    return result;
}

int miller_test(ull a, ull d, ull n) {
    ull x = power_mod(a, d, n);

    if (x == 1 || x == n - 1)
        return 1;

    while (d != n - 1) {
        x = (x * x) % n;
        d <<= 1;

        if (x == 1)
            return 0;
        if (x == n - 1)
            return 1;
    }
    return 0;
}

int is_prime_mr(ull n) {
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if (n % 2 == 0) return 0;

    ull d = n - 1;
    while ((d & 1) == 0)
        d >>= 1;

    ull bases[] = {2, 325, 9375, 28178, 450775, 9780504, 1795265022};

    for (int i = 0; i < 7; i++) {
        ull a = bases[i];
        if (a % n == 0)
            return 1;
        if (!miller_test(a, d, n))
            return 0;
    }
    return 1;
}

int main() {
    ull nums[] = {2, 9223372036854775783ULL};
    int len = sizeof(nums) / sizeof(nums[0]);

    for (int j = 0; j < len; j++) {
        ull n = nums[j];

        printf("\nTesting %llu\n", n);
        printf("-----------------------------\n");

        /* Miller–Rabin */
        clock_t start1 = clock();
        int mr_result = is_prime_mr(n);
        clock_t end1 = clock();

        double mr_time = (double)(end1 - start1) / CLOCKS_PER_SEC;

        /* Trial Division */
        clock_t start2 = clock();
        int trial_result = is_prime_trial(n);
        clock_t end2 = clock();
        double trial_time = (double)(end2 - start2) / CLOCKS_PER_SEC;

        printf("Miller Rabin : %s | time = %.8f sec\n",
               mr_result ? "prime" : "composite",
               mr_time);

        printf("Trial Division : %s | time = %.8f sec\n",
               trial_result ? "prime" : "composite",
               trial_time);
    }

    return 0;
}