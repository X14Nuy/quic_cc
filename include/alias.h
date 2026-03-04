#ifndef ALIAS_H
#define ALIAS_H

#include <stddef.h>
#include <stdint.h>

/*
 * Alias table for O(1) discrete sampling.
 *
 * Given an input discrete PDF p[i], i in [0, n), Walker/Vose Alias Method builds:
 *   - prob[i]  in [0, 1]
 *   - alias[i] in [0, n)
 * so that each sample needs exactly one integer draw and one uniform draw.
 */
typedef struct alias_table_s {
    size_t n;
    double *prob;
    size_t *alias;
    uint64_t total_weight;
} alias_table_t;

/*
 * Build alias table from non-negative integer weights.
 * Return 0 on success, negative value on error.
 */
int alias_table_init(alias_table_t *table, const uint64_t *weights, size_t n);

/* Release resources allocated by alias_table_init. */
void alias_table_free(alias_table_t *table);

/*
 * Sample one index in O(1).
 * rng_u64 must return a 64-bit pseudo-random number.
 */
size_t alias_table_sample(const alias_table_t *table,
                          uint64_t (*rng_u64)(void *),
                          void *rng_ctx);

#endif /* ALIAS_H */
