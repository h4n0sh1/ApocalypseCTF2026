#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INF (1LL << 60)

static int cmp_int(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

int main(void) {
    int n, g;
    if (scanf("%d %d", &n, &g) != 2) return 0;

    static int arr[1205], gate[1505];
    for (int i = 0; i < n; ++i) scanf("%d", &arr[i]);
    for (int j = 0; j < g; ++j) scanf("%d", &gate[j]);

    qsort(arr, n, sizeof(int), cmp_int);
    qsort(gate, g, sizeof(int), cmp_int);

    /* dp[j] after processing convoy i: min cost matching convoys 0..i
       into gates 0..j-1. Rolling 1-D arrays. */
    static long long prev[1506], cur[1506];

    /* base: 0 convoys matched, any prefix of gates -> cost 0 */
    for (int j = 0; j <= g; ++j) prev[j] = 0;

    for (int i = 1; i <= n; ++i) {
        cur[i - 1] = INF; /* fewer gates than convoys: impossible */
        for (int j = i; j <= g; ++j) {
            long long best = cur[j - 1]; /* skip gate j */
            if (gate[j - 1] >= arr[i - 1] && prev[j - 1] < INF) {
                long long c = prev[j - 1] + (gate[j - 1] - arr[i - 1]);
                if (c < best) best = c;
            }
            cur[j] = best;
        }
        memcpy(prev, cur, sizeof(long long) * (g + 1));
    }

    printf("%lld\n", prev[g]);
    return 0;
}
