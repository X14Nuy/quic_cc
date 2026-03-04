#include "alias.h"

#include <stdlib.h>
#include <string.h>

int alias_table_init(alias_table_t *table, const uint64_t *weights, size_t n)
{
    double *scaled = NULL;
    size_t *small = NULL;
    size_t *large = NULL;
    size_t small_top = 0;
    size_t large_top = 0;
    uint64_t sum = 0;
    size_t i;

    if (table == NULL || weights == NULL || n == 0) {
        return -1;
    }

    alias_table_free(table);

    for (i = 0; i < n; ++i) {
        sum += weights[i];
    }
    if (sum == 0) {
        return -2;
    }

    table->prob = (double *)calloc(n, sizeof(double));
    table->alias = (size_t *)calloc(n, sizeof(size_t));
    scaled = (double *)calloc(n, sizeof(double));
    small = (size_t *)calloc(n, sizeof(size_t));
    large = (size_t *)calloc(n, sizeof(size_t));

    if (table->prob == NULL || table->alias == NULL || scaled == NULL ||
        small == NULL || large == NULL) {
        free(scaled);
        free(small);
        free(large);
        alias_table_free(table);
        return -3;
    }

    table->n = n;
    table->total_weight = sum;

    for (i = 0; i < n; ++i) {
        /*
         * scaled[i] = p[i] * n. Values < 1 go to small stack;
         * values >= 1 go to large stack.
         */
        scaled[i] = ((double)weights[i] * (double)n) / (double)sum;
        if (scaled[i] < 1.0) {
            small[small_top++] = i;
        } else {
            large[large_top++] = i;
        }
    }

    while (small_top > 0 && large_top > 0) {
        size_t s = small[--small_top];
        size_t l = large[--large_top];

        table->prob[s] = scaled[s];
        table->alias[s] = l;

        scaled[l] = (scaled[l] + scaled[s]) - 1.0;
        if (scaled[l] < 1.0) {
            small[small_top++] = l;
        } else {
            large[large_top++] = l;
        }
    }

    /* Due to floating-point rounding, residual columns are forced to 1.0. */
    while (large_top > 0) {
        size_t idx = large[--large_top];
        table->prob[idx] = 1.0;
        table->alias[idx] = idx;
    }
    while (small_top > 0) {
        size_t idx = small[--small_top];
        table->prob[idx] = 1.0;
        table->alias[idx] = idx;
    }

    free(scaled);
    free(small);
    free(large);
    return 0;
}

void alias_table_free(alias_table_t *table)
{
    if (table == NULL) {
        return;
    }

    free(table->prob);
    free(table->alias);
    table->prob = NULL;
    table->alias = NULL;
    table->n = 0;
    table->total_weight = 0;
}

size_t alias_table_sample(const alias_table_t *table,
                          uint64_t (*rng_u64)(void *),
                          void *rng_ctx)
{
    uint64_t x;
    uint64_t y;
    size_t column;
    double u;

    if (table == NULL || table->n == 0 || table->prob == NULL ||
        table->alias == NULL || rng_u64 == NULL) {
        return 0;
    }

    x = rng_u64(rng_ctx);
    column = (size_t)(x % table->n);

    y = rng_u64(rng_ctx);
    /* Map top 53 bits to [0, 1), matching IEEE754 double mantissa precision. */
    u = (double)(y >> 11) * (1.0 / 9007199254740992.0);

    return (u < table->prob[column]) ? column : table->alias[column];
}
