#include <stdio.h>
#include <string.h>

int present(char arr[][32], int n, const char *s) {
    for (int i = 0; i < n; ++i) {
        if (strcmp(arr[i], s) == 0) return 1;
    }
    return 0;
}

int main(void) {
    int C;
    if (scanf("%d", &C) != 1) return 0;
    char clerks[21][32];
    for (int i = 0; i < C; ++i) scanf("%31s", clerks[i]);

    int CS;
    scanf("%d", &CS);
    char counters[21][32];
    for (int i = 0; i < CS; ++i) scanf("%31s", counters[i]);

    int R;
    scanf("%d", &R);
    char cours[21][32];
    for (int i = 0; i < R; ++i) scanf("%31s", cours[i]);

    int N;
    scanf("%d", &N);
    char a[64], b[64], c[64];
    int surv = 0;
    for (int i = 0; i < N; ++i) {
        scanf("%63s %63s %63s", a, b, c);
        if (present(clerks, C, a) && present(counters, CS, b) && present(cours, R, c)) {
            ++surv;
        }
    }

    printf("%d\n", surv);
    return 0;
}
