#include <stdio.h>

int main(void)
{
    int n, m, q;
    if (scanf("%d %d %d", &n, &m, &q) != 3)
        return 1;

    int arr[2001]; /* arr[pos] = item currently sitting at pos */
    int queries[2000];
    for (int i = 1; i <= n; i++)
        arr[i] = i;

    for (int i = 0; i < m; i++) {
        int a, b;
        scanf("%d %d", &a, &b);
        int tmp = arr[a];
        arr[a] = arr[b];
        arr[b] = tmp;
    }

    for (int i = 0; i < q; i++)
        scanf("%d", &queries[i]);

    for (int i = 0; i < q; i++) {
        int p = queries[i];
        for (int j = 1; j <= n; j++) {
            if (arr[j] == p) {
                printf("%d\n", j);
                break;
            }
        }
    }

    return 0;
}
