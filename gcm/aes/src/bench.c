#include <psa/crypto.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>

#include "aes_gcm.h"
#include "rijndael_256_gcm.h"
#include "bench.h"

/* ── configuration ──────────────────────────────────────── */
#define WARMUP_ITERS   10
#define BENCH_ITERS   100
#define MESSAGE_LEN   4096
#define AD_LEN         0

/* work buffers */
static uint8_t pt_buf[MESSAGE_LEN];
static uint8_t ct_buf[MESSAGE_LEN];
static uint8_t dec_buf[MESSAGE_LEN];
static uint8_t tag_buf[AES_GCM_TAG_LEN];
static uint8_t tag_buf_r256[RIJNDAEL256_GCM_TAG_LEN];

#if AD_LEN > 0
static uint8_t ad_buf[AD_LEN];
#else
static uint8_t *ad_buf = NULL;
#endif

static const uint8_t bench_key_128[AES128_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

static const uint8_t bench_key_256[AES256_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const uint8_t bench_nonce[AES_GCM_NONCE_LEN] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
    0xa8,0xa9,0xaa,0xab
};

static const uint8_t bench_key_rijndael256[RIJNDAEL256_KEY_LEN] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const uint8_t bench_nonce_rijndael256[RIJNDAEL256_GCM_NONCE_LEN] = {
    0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
    0xb8,0xb9,0xba,0xbb
};

static void fill_pattern(uint8_t *buf, size_t len)
{
    if (!buf || len == 0U) {
        return;
    }

    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i & 0xFFU);
    }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printk("%s", label);
    for (size_t i = 0; i < len; ++i) {
        printk("%02x", buf[i]);
    }
    printk("\n");
}

static bool psa_import_aes_key(const uint8_t *key, size_t key_len, size_t key_bits, psa_key_id_t *key_id)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t st;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, key_bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    st = psa_import_key(&attr, key, key_len, key_id);
    if (st != PSA_SUCCESS) {
        printk("  psa_import_key failed: %d\n", (int)st);
        return false;
    }

    return true;
}

/* ── probe helpers (measure block calls for one operation) ── */

static uint32_t probe_128_block_calls_auth_only(void)
{
    aes_gcm_counters_reset();
    aes_128_gcm_auth(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                     ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    return aes_128_gcm_get_block_calls();
}

static uint32_t probe_128_block_calls_verify_only(void)
{
    aes_gcm_counters_reset();
    (void)aes_128_gcm_verify(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                             ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    return aes_128_gcm_get_block_calls();
}

static uint32_t probe_128_block_calls_encrypt_only(void)
{
    aes_gcm_counters_reset();
    aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    return aes_128_gcm_get_block_calls();
}

static uint32_t probe_128_block_calls_decrypt_only(void)
{
    aes_gcm_counters_reset();
    aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
    return aes_128_gcm_get_block_calls();
}

static uint32_t probe_256_block_calls_auth_only(void)
{
    aes_gcm_counters_reset();
    aes_256_gcm_auth(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                     ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    return aes_256_gcm_get_block_calls();
}

static uint32_t probe_256_block_calls_verify_only(void)
{
    aes_gcm_counters_reset();
    (void)aes_256_gcm_verify(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                             ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    return aes_256_gcm_get_block_calls();
}

static uint32_t probe_256_block_calls_encrypt_only(void)
{
    aes_gcm_counters_reset();
    aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    return aes_256_gcm_get_block_calls();
}

static uint32_t probe_256_block_calls_decrypt_only(void)
{
    aes_gcm_counters_reset();
    aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
    return aes_256_gcm_get_block_calls();
}

static uint32_t probe_rijndael256_block_calls_auth_only(void)
{
    rijndael256_gcm_counters_reset();
    rijndael256_gcm_auth(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                         ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf_r256);
    return rijndael256_gcm_get_block_calls();
}

static uint32_t probe_rijndael256_block_calls_verify_only(void)
{
    rijndael256_gcm_counters_reset();
    (void)rijndael256_gcm_verify(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                                 ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf_r256);
    return rijndael256_gcm_get_block_calls();
}

static uint32_t probe_rijndael256_block_calls_encrypt_only(void)
{
    rijndael256_gcm_counters_reset();
    rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                               pt_buf, MESSAGE_LEN, ct_buf);
    return rijndael256_gcm_get_block_calls();
}

static uint32_t probe_rijndael256_block_calls_decrypt_only(void)
{
    rijndael256_gcm_counters_reset();
    rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                               ct_buf, MESSAGE_LEN, dec_buf);
    return rijndael256_gcm_get_block_calls();
}

/* ── correctness ────────────────────────────────────────── */

static void correctness_128(void)
{
    static const uint8_t test_pt[] = "Hello, AES-128-GCM!";
    uint8_t our_ct[sizeof(test_pt) - 1U];
    uint8_t our_tag[AES_GCM_TAG_LEN];
    uint8_t our_dec[sizeof(test_pt)];
    uint8_t psa_out[(sizeof(test_pt) - 1U) + AES_GCM_TAG_LEN];
    uint8_t psa_ct[sizeof(test_pt) - 1U];
    uint8_t psa_tag[AES_GCM_TAG_LEN];
    uint8_t psa_dec[sizeof(test_pt)];
    size_t out_len = 0;
    size_t dec_len = 0;
    psa_key_id_t key_id;
    psa_status_t st;
    int rc;

    printk("[AES-128-GCM]\n");
    printk("  PT: \"%s\"\n", test_pt);

    aes_128_gcm_encrypt_auth(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                             NULL, 0,
                             test_pt, sizeof(test_pt) - 1U,
                             our_ct, our_tag);
    rc = aes_128_gcm_decrypt_verify(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                                    NULL, 0,
                                    our_ct, sizeof(test_pt) - 1U,
                                    our_tag, our_dec);
    our_dec[sizeof(test_pt) - 1U] = '\0';

    printk("  [Our implementation]\n");
    print_hex("    CT:  ", our_ct, sizeof(test_pt) - 1U);
    print_hex("    TAG: ", our_tag, AES_GCM_TAG_LEN);
    printk("    DEC: %s\n", our_dec);
    printk("    verify: %s\n", rc == 0 ? "OK" : "FAIL");

    if (!psa_import_aes_key(bench_key_128, sizeof(bench_key_128), 128U, &key_id)) {
        printk("\n");
        return;
    }

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          bench_nonce, sizeof(bench_nonce),
                          NULL, 0,
                          test_pt, sizeof(test_pt) - 1U,
                          psa_out, sizeof(psa_out), &out_len);
    if (st != PSA_SUCCESS) {
        printk("  [PSA]\n    encrypt failed: %d\n\n", (int)st);
        psa_destroy_key(key_id);
        return;
    }

    memcpy(psa_ct, psa_out, sizeof(test_pt) - 1U);
    memcpy(psa_tag, psa_out + (sizeof(test_pt) - 1U), AES_GCM_TAG_LEN);

    st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                          bench_nonce, sizeof(bench_nonce),
                          NULL, 0,
                          psa_out, out_len,
                          psa_dec, sizeof(psa_dec), &dec_len);
    psa_dec[sizeof(test_pt) - 1U] = '\0';

    printk("  [PSA Crypto]\n");
    print_hex("    CT:  ", psa_ct, sizeof(test_pt) - 1U);
    print_hex("    TAG: ", psa_tag, AES_GCM_TAG_LEN);
    printk("    DEC: %s\n", psa_dec);
    printk("    verify: %s\n", st == PSA_SUCCESS ? "OK" : "FAIL");

    printk("  [CT match]  %s\n",
           memcmp(our_ct, psa_ct, sizeof(test_pt) - 1U) == 0 ? "OK" : "MISMATCH");
    printk("  [TAG match] %s\n\n",
           memcmp(our_tag, psa_tag, AES_GCM_TAG_LEN) == 0 ? "OK" : "MISMATCH");

    psa_destroy_key(key_id);
}

static void correctness_256(void)
{
    static const uint8_t test_pt[] = "Hello, AES-256-GCM!";
    uint8_t our_ct[sizeof(test_pt) - 1U];
    uint8_t our_tag[AES_GCM_TAG_LEN];
    uint8_t our_dec[sizeof(test_pt)];
    uint8_t psa_out[(sizeof(test_pt) - 1U) + AES_GCM_TAG_LEN];
    uint8_t psa_ct[sizeof(test_pt) - 1U];
    uint8_t psa_tag[AES_GCM_TAG_LEN];
    uint8_t psa_dec[sizeof(test_pt)];
    size_t out_len = 0;
    size_t dec_len = 0;
    psa_key_id_t key_id;
    psa_status_t st;
    int rc;

    printk("[AES-256-GCM]\n");
    printk("  PT: \"%s\"\n", test_pt);

    aes_256_gcm_encrypt_auth(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                             NULL, 0,
                             test_pt, sizeof(test_pt) - 1U,
                             our_ct, our_tag);
    rc = aes_256_gcm_decrypt_verify(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                                    NULL, 0,
                                    our_ct, sizeof(test_pt) - 1U,
                                    our_tag, our_dec);
    our_dec[sizeof(test_pt) - 1U] = '\0';

    printk("  [Our implementation]\n");
    print_hex("    CT:  ", our_ct, sizeof(test_pt) - 1U);
    print_hex("    TAG: ", our_tag, AES_GCM_TAG_LEN);
    printk("    DEC: %s\n", our_dec);
    printk("    verify: %s\n", rc == 0 ? "OK" : "FAIL");

    if (!psa_import_aes_key(bench_key_256, sizeof(bench_key_256), 256U, &key_id)) {
        printk("\n");
        return;
    }

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          bench_nonce, sizeof(bench_nonce),
                          NULL, 0,
                          test_pt, sizeof(test_pt) - 1U,
                          psa_out, sizeof(psa_out), &out_len);
    if (st != PSA_SUCCESS) {
        printk("  [PSA]\n    encrypt failed: %d\n\n", (int)st);
        psa_destroy_key(key_id);
        return;
    }

    memcpy(psa_ct, psa_out, sizeof(test_pt) - 1U);
    memcpy(psa_tag, psa_out + (sizeof(test_pt) - 1U), AES_GCM_TAG_LEN);

    st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                          bench_nonce, sizeof(bench_nonce),
                          NULL, 0,
                          psa_out, out_len,
                          psa_dec, sizeof(psa_dec), &dec_len);
    psa_dec[sizeof(test_pt) - 1U] = '\0';

    printk("  [PSA Crypto]\n");
    print_hex("    CT:  ", psa_ct, sizeof(test_pt) - 1U);
    print_hex("    TAG: ", psa_tag, AES_GCM_TAG_LEN);
    printk("    DEC: %s\n", psa_dec);
    printk("    verify: %s\n", st == PSA_SUCCESS ? "OK" : "FAIL");

    printk("  [CT match]  %s\n",
           memcmp(our_ct, psa_ct, sizeof(test_pt) - 1U) == 0 ? "OK" : "MISMATCH");
    printk("  [TAG match] %s\n\n",
           memcmp(our_tag, psa_tag, AES_GCM_TAG_LEN) == 0 ? "OK" : "MISMATCH");

    psa_destroy_key(key_id);
}

static void correctness_rijndael256(void)
{
    static const uint8_t test_pt[] = "Hello, Rijndael-256-GCM!";
    uint8_t our_ct[sizeof(test_pt) - 1U];
    uint8_t our_tag[RIJNDAEL256_GCM_TAG_LEN];
    uint8_t our_dec[sizeof(test_pt)];
    int rc;

    printk("[Rijndael-256-GCM]\n");
    printk("  PT: \"%s\"\n", test_pt);

    rijndael256_gcm_encrypt_auth(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                                 NULL, 0,
                                 test_pt, sizeof(test_pt) - 1U,
                                 our_ct, our_tag);
    rc = rijndael256_gcm_decrypt_verify(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                                        NULL, 0,
                                        our_ct, sizeof(test_pt) - 1U,
                                        our_tag, our_dec);
    our_dec[sizeof(test_pt) - 1U] = '\0';

    printk("  [Our implementation]\n");
    print_hex("    CT:  ", our_ct, sizeof(test_pt) - 1U);
    print_hex("    TAG: ", our_tag, RIJNDAEL256_GCM_TAG_LEN);
    printk("    DEC: %s\n", our_dec);
    printk("    verify: %s\n\n", rc == 1 ? "OK" : "FAIL");
}

void verify_correctness(void)
{
    printk("--- Correctness ---\n\n");
    correctness_128();
    correctness_256();
    correctness_rijndael256();
}

/* ── AES-128 benchmarks ─────────────────────────────────── */

static void bench_128_auth_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    block_calls = probe_128_block_calls_auth_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        aes_128_gcm_auth(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                         ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        aes_128_gcm_auth(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                         ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "auth only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_128_verify_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    aes_128_gcm_encrypt_auth(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                             ad_buf, AD_LEN, pt_buf, MESSAGE_LEN, ct_buf, tag_buf);
    block_calls = probe_128_block_calls_verify_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        (void)aes_128_gcm_verify(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                                 ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        (void)aes_128_gcm_verify(bench_key_128, bench_nonce, AES_GCM_NONCE_LEN,
                                 ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "verify only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_128_encrypt_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    block_calls = probe_128_block_calls_encrypt_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "encrypt only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_128_decrypt_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    block_calls = probe_128_block_calls_decrypt_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        aes_128_gcm_ctr_crypt(bench_key_128, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "decrypt only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_128_psa_encrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    psa_key_id_t key_id;
    static uint8_t out[MESSAGE_LEN + AES_GCM_TAG_LEN];
    size_t out_len = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);

    if (!psa_import_aes_key(bench_key_128, sizeof(bench_key_128), 128U, &key_id)) {
        return;
    }

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        (void)psa_aead_encrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               pt_buf, MESSAGE_LEN,
                               out, sizeof(out), &out_len);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        (void)psa_aead_encrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               pt_buf, MESSAGE_LEN,
                               out, sizeof(out), &out_len);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c += c;
        total_ns += timing_cycles_to_ns(c);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "psa encrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));

    psa_destroy_key(key_id);
}

static void bench_128_psa_decrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    psa_key_id_t key_id;
    static uint8_t enc[MESSAGE_LEN + AES_GCM_TAG_LEN];
    static uint8_t dec[MESSAGE_LEN];
    size_t enc_len = 0;
    size_t dec_len = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);

    if (!psa_import_aes_key(bench_key_128, sizeof(bench_key_128), 128U, &key_id)) {
        return;
    }

    (void)psa_aead_encrypt(key_id, PSA_ALG_GCM,
                           bench_nonce, sizeof(bench_nonce),
                           ad_buf, AD_LEN,
                           pt_buf, MESSAGE_LEN,
                           enc, sizeof(enc), &enc_len);

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        (void)psa_aead_decrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               enc, enc_len,
                               dec, sizeof(dec), &dec_len);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        (void)psa_aead_decrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               enc, enc_len,
                               dec, sizeof(dec), &dec_len);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c += c;
        total_ns += timing_cycles_to_ns(c);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "psa decrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));

    psa_destroy_key(key_id);
}

/* ── AES-256 benchmarks ─────────────────────────────────── */

static void bench_256_auth_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    block_calls = probe_256_block_calls_auth_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        aes_256_gcm_auth(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                         ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        aes_256_gcm_auth(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                         ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "auth only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_256_verify_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    aes_256_gcm_encrypt_auth(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                             ad_buf, AD_LEN, pt_buf, MESSAGE_LEN, ct_buf, tag_buf);
    block_calls = probe_256_block_calls_verify_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        (void)aes_256_gcm_verify(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                                 ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        (void)aes_256_gcm_verify(bench_key_256, bench_nonce, AES_GCM_NONCE_LEN,
                                 ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "verify only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_256_encrypt_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    block_calls = probe_256_block_calls_encrypt_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "encrypt only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_256_decrypt_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, pt_buf, MESSAGE_LEN, ct_buf);
    block_calls = probe_256_block_calls_decrypt_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        aes_256_gcm_ctr_crypt(bench_key_256, bench_nonce, ct_buf, MESSAGE_LEN, dec_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "decrypt only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [aes block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_256_psa_encrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    psa_key_id_t key_id;
    static uint8_t out[MESSAGE_LEN + AES_GCM_TAG_LEN];
    size_t out_len = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);

    if (!psa_import_aes_key(bench_key_256, sizeof(bench_key_256), 256U, &key_id)) {
        return;
    }

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        (void)psa_aead_encrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               pt_buf, MESSAGE_LEN,
                               out, sizeof(out), &out_len);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        (void)psa_aead_encrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               pt_buf, MESSAGE_LEN,
                               out, sizeof(out), &out_len);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c += c;
        total_ns += timing_cycles_to_ns(c);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "psa encrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));

    psa_destroy_key(key_id);
}

static void bench_256_psa_decrypt(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    psa_key_id_t key_id;
    static uint8_t enc[MESSAGE_LEN + AES_GCM_TAG_LEN];
    static uint8_t dec[MESSAGE_LEN];
    size_t enc_len = 0;
    size_t dec_len = 0;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);

    if (!psa_import_aes_key(bench_key_256, sizeof(bench_key_256), 256U, &key_id)) {
        return;
    }

    (void)psa_aead_encrypt(key_id, PSA_ALG_GCM,
                           bench_nonce, sizeof(bench_nonce),
                           ad_buf, AD_LEN,
                           pt_buf, MESSAGE_LEN,
                           enc, sizeof(enc), &enc_len);

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        (void)psa_aead_decrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               enc, enc_len,
                               dec, sizeof(dec), &dec_len);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        (void)psa_aead_decrypt(key_id, PSA_ALG_GCM,
                               bench_nonce, sizeof(bench_nonce),
                               ad_buf, AD_LEN,
                               enc, enc_len,
                               dec, sizeof(dec), &dec_len);
        end = timing_counter_get();
        uint64_t c = timing_cycles_get(&start, &end);
        total_c += c;
        total_ns += timing_cycles_to_ns(c);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "psa decrypt",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));

    psa_destroy_key(key_id);
}

/* ── Rijndael-256 benchmarks ────────────────────────────── */

static void bench_rijndael256_auth_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                               pt_buf, MESSAGE_LEN, ct_buf);
    block_calls = probe_rijndael256_block_calls_auth_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        rijndael256_gcm_auth(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                             ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf_r256);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        rijndael256_gcm_auth(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                             ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf_r256);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "auth only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [rijndael block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_rijndael256_verify_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    fill_pattern(ad_buf, AD_LEN);
    rijndael256_gcm_encrypt_auth(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                                 ad_buf, AD_LEN, pt_buf, MESSAGE_LEN, ct_buf, tag_buf_r256);
    block_calls = probe_rijndael256_block_calls_verify_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        (void)rijndael256_gcm_verify(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                                     ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf_r256);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        (void)rijndael256_gcm_verify(bench_key_rijndael256, bench_nonce_rijndael256, RIJNDAEL256_GCM_NONCE_LEN,
                                     ad_buf, AD_LEN, ct_buf, MESSAGE_LEN, tag_buf_r256);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "verify only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [rijndael block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_rijndael256_encrypt_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    block_calls = probe_rijndael256_block_calls_encrypt_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                                   pt_buf, MESSAGE_LEN, ct_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                                   pt_buf, MESSAGE_LEN, ct_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "encrypt only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [rijndael block/op] %lu\n", (unsigned long)block_calls);
}

static void bench_rijndael256_decrypt_only(void)
{
    timing_t start, end;
    uint64_t total_c = 0;
    uint64_t total_ns = 0;
    uint32_t block_calls;

    fill_pattern(pt_buf, MESSAGE_LEN);
    rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                               pt_buf, MESSAGE_LEN, ct_buf);
    block_calls = probe_rijndael256_block_calls_decrypt_only();

    for (int i = 0; i < WARMUP_ITERS; ++i) {
        rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                                   ct_buf, MESSAGE_LEN, dec_buf);
    }

    for (int i = 0; i < BENCH_ITERS; ++i) {
        start = timing_counter_get();
        rijndael256_gcm_ctr_crypt(bench_key_rijndael256, bench_nonce_rijndael256,
                                   ct_buf, MESSAGE_LEN, dec_buf);
        end = timing_counter_get();
        uint64_t c2 = timing_cycles_get(&start, &end);
        total_c += c2;
        total_ns += timing_cycles_to_ns(c2);
    }

    printk("  %-16s: %10llu cycles  |  %10llu ns\n", "decrypt only",
           (unsigned long long)(total_c / BENCH_ITERS),
           (unsigned long long)(total_ns / BENCH_ITERS));
    printk("    [rijndael block/op] %lu\n", (unsigned long)block_calls);
}

/* ── top-level entry ───────────────────────────────────── */

void bench_gcm_all(void)
{
    printk("--- Timing ---\n\n");

    printk("[AES-128-GCM] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  sizes: key=%d nonce=%d tag=%d pt=%d ct=%d ad=%d\n",
           AES128_KEY_LEN, AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN,
           MESSAGE_LEN, MESSAGE_LEN, AD_LEN);
    printk("  %-16s  %10s  %12s\n", "operation", "cycles", "ns");
    printk("  [Our implementation]\n");
    bench_128_auth_only();
    bench_128_verify_only();
    bench_128_encrypt_only();
    bench_128_decrypt_only();
    printk("  [PSA Crypto]\n");
    bench_128_psa_encrypt();
    bench_128_psa_decrypt();
    printk("\n");

    printk("[AES-256-GCM] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  sizes: key=%d nonce=%d tag=%d pt=%d ct=%d ad=%d\n",
           AES256_KEY_LEN, AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN,
           MESSAGE_LEN, MESSAGE_LEN, AD_LEN);
    printk("  %-16s  %10s  %12s\n", "operation", "cycles", "ns");
    printk("  [Our implementation]\n");
    bench_256_auth_only();
    bench_256_verify_only();
    bench_256_encrypt_only();
    bench_256_decrypt_only();
    printk("  [PSA Crypto]\n");
    bench_256_psa_encrypt();
    bench_256_psa_decrypt();
    printk("\n");

    printk("[Rijndael-256-GCM] Benchmark  msg=%d ad=%d iters=%d\n",
           MESSAGE_LEN, AD_LEN, BENCH_ITERS);
    printk("  sizes: key=%d nonce=%d tag=%d pt=%d ct=%d ad=%d\n",
           RIJNDAEL256_KEY_LEN, RIJNDAEL256_GCM_NONCE_LEN, RIJNDAEL256_GCM_TAG_LEN,
           MESSAGE_LEN, MESSAGE_LEN, AD_LEN);
    printk("  %-16s  %10s  %12s\n", "operation", "cycles", "ns");
    printk("  [Our implementation]\n");
    bench_rijndael256_auth_only();
    bench_rijndael256_verify_only();
    bench_rijndael256_encrypt_only();
    bench_rijndael256_decrypt_only();
    printk("\n--- Benchmark complete ---\n");
}
