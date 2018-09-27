/**********************************************************************
 * Copyright (c) 2015 Gregory Maxwell                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RANGEPROOF_TESTS
#define SECP256K1_MODULE_RANGEPROOF_TESTS

#include <string.h>
#include <inttypes.h>
#include <time.h>

#include "group.h"
#include "scalar.h"
#include "testrand.h"
#include "util.h"

#include "include/secp256k1_rangeproof.h"

static void test_pedersen_api(const secp256k1_context *none, const secp256k1_context *sign, const secp256k1_context *vrfy, const int32_t *ecount) {
    secp256k1_pedersen_commitment commit;
    const secp256k1_pedersen_commitment *commit_ptr = &commit;
    unsigned char blind[32];
    unsigned char blind_out[32];
    const unsigned char *blind_ptr = blind;
    unsigned char *blind_out_ptr = blind_out;
    uint64_t val = secp256k1_rand32();

    secp256k1_rand256(blind);
    CHECK(secp256k1_pedersen_commit(none, &commit, blind, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 1);
    CHECK(secp256k1_pedersen_commit(vrfy, &commit, blind, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 2);
    CHECK(secp256k1_pedersen_commit(sign, &commit, blind, val, secp256k1_generator_h) != 0);
    CHECK(*ecount == 2);

    CHECK(secp256k1_pedersen_commit(sign, NULL, blind, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 3);
    CHECK(secp256k1_pedersen_commit(sign, &commit, NULL, val, secp256k1_generator_h) == 0);
    CHECK(*ecount == 4);
    CHECK(secp256k1_pedersen_commit(sign, &commit, blind, val, NULL) == 0);
    CHECK(*ecount == 5);

    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, &blind_ptr, 1, 1) != 0);
    CHECK(*ecount == 5);
    CHECK(secp256k1_pedersen_blind_sum(none, NULL, &blind_ptr, 1, 1) == 0);
    CHECK(*ecount == 6);
    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, NULL, 1, 1) == 0);
    CHECK(*ecount == 7);
    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, &blind_ptr, 0, 1) == 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_pedersen_blind_sum(none, blind_out, &blind_ptr, 0, 0) != 0);
    CHECK(*ecount == 8);

    CHECK(secp256k1_pedersen_commit(sign, &commit, blind, val, secp256k1_generator_h) != 0);
    CHECK(secp256k1_pedersen_verify_tally(none, &commit_ptr, 1, &commit_ptr, 1) != 0);
    CHECK(secp256k1_pedersen_verify_tally(none, NULL, 0, &commit_ptr, 1) == 0);
    CHECK(secp256k1_pedersen_verify_tally(none, &commit_ptr, 1, NULL, 0) == 0);
    CHECK(secp256k1_pedersen_verify_tally(none, NULL, 0, NULL, 0) != 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_pedersen_verify_tally(none, NULL, 1, &commit_ptr, 1) == 0);
    CHECK(*ecount == 9);
    CHECK(secp256k1_pedersen_verify_tally(none, &commit_ptr, 1, NULL, 1) == 0);
    CHECK(*ecount == 10);

    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, &blind_out_ptr, 1, 0) != 0);
    CHECK(*ecount == 10);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, &blind_out_ptr, 1, 1) == 0);
    CHECK(*ecount == 11);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, &blind_out_ptr, 0, 0) == 0);
    CHECK(*ecount == 12);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, NULL, &blind_ptr, &blind_out_ptr, 1, 0) == 0);
    CHECK(*ecount == 13);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, NULL, &blind_out_ptr, 1, 0) == 0);
    CHECK(*ecount == 14);
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(none, &val, &blind_ptr, NULL, 1, 0) == 0);
    CHECK(*ecount == 15);
}

static void test_rangeproof_api(const secp256k1_context *none, const secp256k1_context *sign, const secp256k1_context *vrfy, const secp256k1_context *both, const int32_t *ecount) {
    unsigned char proof[5134];
    unsigned char blind[32];
    secp256k1_pedersen_commitment commit;
    uint64_t vmin = secp256k1_rand32();
    uint64_t val = vmin + secp256k1_rand32();
    size_t len = sizeof(proof);
    /* we'll switch to dylan thomas for this one */
    const unsigned char message[68] = "My tears are like the quiet drift / Of petals from some magic rose;";
    size_t mlen = sizeof(message);
    const unsigned char ext_commit[72] = "And all my grief flows from the rift / Of unremembered skies and snows.";
    size_t ext_commit_len = sizeof(ext_commit);

    secp256k1_rand256(blind);
    CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, val, secp256k1_generator_h));

    CHECK(secp256k1_rangeproof_sign(none, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 1);
    CHECK(secp256k1_rangeproof_sign(sign, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 2);
    CHECK(secp256k1_rangeproof_sign(vrfy, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 3);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
    CHECK(*ecount == 3);

    CHECK(secp256k1_rangeproof_sign(both, NULL, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 4);
    CHECK(secp256k1_rangeproof_sign(both, proof, NULL, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 5);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, NULL, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 6);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, NULL, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 7);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, NULL, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, vmin - 1, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 8);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 9);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
    CHECK(*ecount == 9);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, NULL, ext_commit_len, secp256k1_generator_h) == 0);
    CHECK(*ecount == 10);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, NULL, 0, secp256k1_generator_h) != 0);
    CHECK(*ecount == 10);
    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, NULL, 0, NULL, 0, NULL) == 0);
    CHECK(*ecount == 11);

    CHECK(secp256k1_rangeproof_sign(both, proof, &len, vmin, &commit, blind, commit.data, 0, 0, val, message, mlen, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
    {
        int exp;
        int mantissa;
        uint64_t min_value;
        uint64_t max_value;
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, &max_value, proof, len) != 0);
        CHECK(exp == 0);
        CHECK(((uint64_t) 1 << mantissa) > val - vmin);
        CHECK(((uint64_t) 1 << (mantissa - 1)) <= val - vmin);
        CHECK(min_value == vmin);
        CHECK(max_value >= val);

        CHECK(secp256k1_rangeproof_info(none, NULL, &mantissa, &min_value, &max_value, proof, len) == 0);
        CHECK(*ecount == 12);
        CHECK(secp256k1_rangeproof_info(none, &exp, NULL, &min_value, &max_value, proof, len) == 0);
        CHECK(*ecount == 13);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, NULL, &max_value, proof, len) == 0);
        CHECK(*ecount == 14);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, NULL, proof, len) == 0);
        CHECK(*ecount == 15);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, &max_value, NULL, len) == 0);
        CHECK(*ecount == 16);
        CHECK(secp256k1_rangeproof_info(none, &exp, &mantissa, &min_value, &max_value, proof, 0) == 0);
        CHECK(*ecount == 16);
    }
    {
        uint64_t min_value;
        uint64_t max_value;
        CHECK(secp256k1_rangeproof_verify(none, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 17);
        CHECK(secp256k1_rangeproof_verify(sign, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 18);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 18);

        CHECK(secp256k1_rangeproof_verify(vrfy, NULL, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 19);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, NULL, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 20);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, NULL, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 21);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, NULL, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 22);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, 0, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 22);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, NULL, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 23);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, NULL, 0, secp256k1_generator_h) == 0);
        CHECK(*ecount == 23);
        CHECK(secp256k1_rangeproof_verify(vrfy, &min_value, &max_value, &commit, proof, len, NULL, 0, NULL) == 0);
        CHECK(*ecount == 24);
    }
    {
        unsigned char blind_out[32];
        unsigned char message_out[68];
        uint64_t value_out;
        uint64_t min_value;
        uint64_t max_value;
        size_t message_len = sizeof(message_out);

        CHECK(secp256k1_rangeproof_rewind(none, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 25);
        CHECK(secp256k1_rangeproof_rewind(sign, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 26);
        CHECK(secp256k1_rangeproof_rewind(vrfy, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 27);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 27);

        CHECK(min_value == vmin);
        CHECK(max_value >= val);
        CHECK(value_out == val);
        CHECK(message_len == sizeof(message_out));
        CHECK(memcmp(message, message_out, sizeof(message_out)) == 0);

        CHECK(secp256k1_rangeproof_rewind(both, NULL, &value_out, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 27);  /* blindout may be NULL */
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, NULL, message_out, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 27);  /* valueout may be NULL */
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, &message_len, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 28);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) != 0);
        CHECK(*ecount == 28);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, NULL, &min_value, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 29);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, NULL, &max_value, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 30);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, NULL, &commit, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 31);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, NULL, proof, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 32);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, NULL, len, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 33);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, 0, ext_commit, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 33);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, NULL, ext_commit_len, secp256k1_generator_h) == 0);
        CHECK(*ecount == 34);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, NULL, 0, secp256k1_generator_h) == 0);
        CHECK(*ecount == 34);
        CHECK(secp256k1_rangeproof_rewind(both, blind_out, &value_out, NULL, 0, commit.data, &min_value, &max_value, &commit, proof, len, NULL, 0, NULL) == 0);
        CHECK(*ecount == 35);
    }
}

static void test_api(void) {
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int32_t ecount;
    int i;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    for (i = 0; i < count; i++) {
        ecount = 0;
        test_pedersen_api(none, sign, vrfy, &ecount);
        ecount = 0;
        test_rangeproof_api(none, sign, vrfy, both, &ecount);
    }

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

static void test_pedersen(void) {
    secp256k1_pedersen_commitment commits[19];
    const secp256k1_pedersen_commitment *cptr[19];
    unsigned char blinds[32*19];
    const unsigned char *bptr[19];
    secp256k1_scalar s;
    uint64_t values[19];
    int64_t totalv;
    int i;
    int inputs;
    int outputs;
    int total;
    inputs = (secp256k1_rand32() & 7) + 1;
    outputs = (secp256k1_rand32() & 7) + 2;
    total = inputs + outputs;
    for (i = 0; i < 19; i++) {
        cptr[i] = &commits[i];
        bptr[i] = &blinds[i * 32];
    }
    totalv = 0;
    for (i = 0; i < inputs; i++) {
        values[i] = secp256k1_rands64(0, INT64_MAX - totalv);
        totalv += values[i];
    }
    for (i = 0; i < outputs - 1; i++) {
        values[i + inputs] = secp256k1_rands64(0, totalv);
        totalv -= values[i + inputs];
    }
    values[total - 1] = totalv;

    for (i = 0; i < total - 1; i++) {
        random_scalar_order(&s);
        secp256k1_scalar_get_b32(&blinds[i * 32], &s);
    }
    CHECK(secp256k1_pedersen_blind_sum(ctx, &blinds[(total - 1) * 32], bptr, total - 1, inputs));
    for (i = 0; i < total; i++) {
        CHECK(secp256k1_pedersen_commit(ctx, &commits[i], &blinds[i * 32], values[i], secp256k1_generator_h));
    }
    CHECK(secp256k1_pedersen_verify_tally(ctx, cptr, inputs, &cptr[inputs], outputs));
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[inputs], outputs, cptr, inputs));
    if (inputs > 0 && values[0] > 0) {
        CHECK(!secp256k1_pedersen_verify_tally(ctx, cptr, inputs - 1, &cptr[inputs], outputs));
    }
    random_scalar_order(&s);
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_get_b32(&blinds[i * 32], &s);
    }
    values[0] = INT64_MAX;
    values[1] = 0;
    values[2] = 1;
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_pedersen_commit(ctx, &commits[i], &blinds[i * 32], values[i], secp256k1_generator_h));
    }
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[0], 1, &cptr[0], 1));
    CHECK(secp256k1_pedersen_verify_tally(ctx, &cptr[1], 1, &cptr[1], 1));
}

static void test_borromean(void) {
    unsigned char e0[32];
    secp256k1_scalar s[64];
    secp256k1_gej pubs[64];
    secp256k1_scalar k[8];
    secp256k1_scalar sec[8];
    secp256k1_ge ge;
    secp256k1_scalar one;
    unsigned char m[32];
    size_t rsizes[8];
    size_t secidx[8];
    size_t nrings;
    size_t i;
    size_t j;
    int c;
    secp256k1_rand256_test(m);
    nrings = 1 + (secp256k1_rand32()&7);
    c = 0;
    secp256k1_scalar_set_int(&one, 1);
    if (secp256k1_rand32()&1) {
        secp256k1_scalar_negate(&one, &one);
    }
    for (i = 0; i < nrings; i++) {
        rsizes[i] = 1 + (secp256k1_rand32()&7);
        secidx[i] = secp256k1_rand32() % rsizes[i];
        random_scalar_order(&sec[i]);
        random_scalar_order(&k[i]);
        if(secp256k1_rand32()&7) {
            sec[i] = one;
        }
        if(secp256k1_rand32()&7) {
            k[i] = one;
        }
        for (j = 0; j < rsizes[i]; j++) {
            random_scalar_order(&s[c + j]);
            if(secp256k1_rand32()&7) {
                s[i] = one;
            }
            if (j == secidx[i]) {
                secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubs[c + j], &sec[i]);
            } else {
                random_group_element_test(&ge);
                random_group_element_jacobian_test(&pubs[c + j],&ge);
            }
        }
        c += rsizes[i];
    }
    CHECK(secp256k1_borromean_sign(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx, e0, s, pubs, k, sec, rsizes, secidx, nrings, m, 32));
    CHECK(secp256k1_borromean_verify(&ctx->ecmult_ctx, NULL, e0, s, pubs, rsizes, nrings, m, 32));
    i = secp256k1_rand32() % c;
    secp256k1_scalar_negate(&s[i],&s[i]);
    CHECK(!secp256k1_borromean_verify(&ctx->ecmult_ctx, NULL, e0, s, pubs, rsizes, nrings, m, 32));
    secp256k1_scalar_negate(&s[i],&s[i]);
    secp256k1_scalar_set_int(&one, 1);
    for(j = 0; j < 4; j++) {
        i = secp256k1_rand32() % c;
        if (secp256k1_rand32() & 1) {
            secp256k1_gej_double_var(&pubs[i],&pubs[i], NULL);
        } else {
            secp256k1_scalar_add(&s[i],&s[i],&one);
        }
        CHECK(!secp256k1_borromean_verify(&ctx->ecmult_ctx, NULL, e0, s, pubs, rsizes, nrings, m, 32));
    }
}

static void test_rangeproof(void) {
    secp256k1_pedersen_commitment commit;
    unsigned char proof[5134];
    unsigned char blind[32];
    uint64_t v;
    uint64_t minv;
    uint64_t maxv;
    size_t len;

    secp256k1_rand256(blind);
    v = secp256k1_rand_bits(32);
    CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, v, secp256k1_generator_h));
    len = 5134;
    CHECK(secp256k1_rangeproof_sign(ctx, proof, &len, 0, &commit, blind, commit.data, 0, 32, v, NULL, 0, NULL, 0, secp256k1_generator_h));
    clock_t tStart = clock();
    CHECK(secp256k1_rangeproof_verify(ctx, &minv, &maxv, &commit, proof, len, NULL, 0, secp256k1_generator_h));
    printf("Time taken: %.2f ms\n", (double)(clock() - tStart)/CLOCKS_PER_SEC*1000);
}

#define MAX_N_GENS	30
void test_multiple_generators(void) {
    const size_t n_inputs = (secp256k1_rand32() % (MAX_N_GENS / 2)) + 1;
    const size_t n_outputs = (secp256k1_rand32() % (MAX_N_GENS / 2)) + 1;
    const size_t n_generators = n_inputs + n_outputs;
    unsigned char *generator_blind[MAX_N_GENS];
    unsigned char *pedersen_blind[MAX_N_GENS];
    secp256k1_generator generator[MAX_N_GENS];
    secp256k1_pedersen_commitment commit[MAX_N_GENS];
    const secp256k1_pedersen_commitment *commit_ptr[MAX_N_GENS];
    size_t i;
    int64_t total_value;
    uint64_t value[MAX_N_GENS];

    secp256k1_scalar s;

    unsigned char generator_seed[32];
    random_scalar_order(&s);
    secp256k1_scalar_get_b32(generator_seed, &s);
    /* Create all the needed generators */
    for (i = 0; i < n_generators; i++) {
        generator_blind[i] = (unsigned char*) malloc(32);
        pedersen_blind[i] = (unsigned char*) malloc(32);

        random_scalar_order(&s);
        secp256k1_scalar_get_b32(generator_blind[i], &s);
        random_scalar_order(&s);
        secp256k1_scalar_get_b32(pedersen_blind[i], &s);

        CHECK(secp256k1_generator_generate_blinded(ctx, &generator[i], generator_seed, generator_blind[i]));

        commit_ptr[i] = &commit[i];
    }

    /* Compute all the values -- can be positive or negative */
    total_value = 0;
    for (i = 0; i < n_outputs; i++) {
        value[n_inputs + i] = secp256k1_rands64(0, INT64_MAX - total_value);
        total_value += value[n_inputs + i];
    }
    for (i = 0; i < n_inputs - 1; i++) {
        value[i] = secp256k1_rands64(0, total_value);
        total_value -= value[i];
    }
    value[i] = total_value;

    /* Correct for blinding factors and do the commitments */
    CHECK(secp256k1_pedersen_blind_generator_blind_sum(ctx, value, (const unsigned char * const *) generator_blind, pedersen_blind, n_generators, n_inputs));
    for (i = 0; i < n_generators; i++) {
        CHECK(secp256k1_pedersen_commit(ctx, &commit[i], pedersen_blind[i], value[i], &generator[i]));
    }

    /* Verify */
    CHECK(secp256k1_pedersen_verify_tally(ctx, &commit_ptr[0], n_inputs, &commit_ptr[n_inputs], n_outputs));

    /* Cleanup */
    for (i = 0; i < n_generators; i++) {
        free(generator_blind[i]);
        free(pedersen_blind[i]);
    }
}

void run_rangeproof_tests(void) {
    int i;
    for (i = 0; i < count; i++){
        test_rangeproof();
    }
}

#endif
