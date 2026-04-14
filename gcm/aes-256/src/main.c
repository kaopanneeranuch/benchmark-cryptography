#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/timing/timing.h>
#include <psa/crypto.h>
#include <string.h>
#include "aesgcm.h"
#include "bench.h"

/* ── shared test vector ─────────────────────────────────── */
static const uint8_t TEST_KEY[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t TEST_NONCE[12] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab
};
static const uint8_t TEST_PT[] = "Hello, AES-256-GCM!";
#define TEST_PT_LEN  (sizeof(TEST_PT) - 1)

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printk("  %-8s", label);
    for (size_t i = 0; i < len; i++) printk("%02x", buf[i]);
    printk("\n");
}

/* ── correctness ────────────────────────────────────────── */
static void correctness_our_impl(uint8_t *ct_out, uint8_t *tag_out)
{
    printk("[Our AES-256-GCM]\n");
    aes_gcm_encrypt(TEST_KEY, TEST_NONCE, NULL, 0,
                    TEST_PT, TEST_PT_LEN, ct_out, tag_out);
    print_hex("CT:", ct_out, TEST_PT_LEN);
    print_hex("TAG:", tag_out, 16);

    uint8_t dec[TEST_PT_LEN];
    int rc = aes_gcm_decrypt(TEST_KEY, TEST_NONCE, NULL, 0,
                              ct_out, TEST_PT_LEN, tag_out, dec);
    dec[TEST_PT_LEN] = '\0';
    printk("  DEC:    %s\n", dec);
    printk("  verify: %s\n\n", rc == 0 ? "OK" : "FAIL");
}

static void correctness_psa(uint8_t *ct_out, uint8_t *tag_out)
{
    printk("[PSA AES-256-GCM]\n");

    psa_key_id_t key;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_status_t st = psa_import_key(&attr, TEST_KEY, sizeof(TEST_KEY), &key);
    if (st != PSA_SUCCESS) { printk("  import_key failed: %d\n", (int)st); return; }

    /* PSA output = ciphertext || tag (16 bytes) */
    uint8_t output[TEST_PT_LEN + 16];
    size_t out_len;
    st = psa_aead_encrypt(key, PSA_ALG_GCM,
                           TEST_NONCE, sizeof(TEST_NONCE),
                           NULL, 0,
                           TEST_PT, TEST_PT_LEN,
                           output, sizeof(output), &out_len);
    if (st != PSA_SUCCESS) {
        printk("  encrypt failed: %d\n", (int)st);
        psa_destroy_key(key);
        return;
    }
    memcpy(ct_out,  output,              TEST_PT_LEN);
    memcpy(tag_out, output + TEST_PT_LEN, 16);
    print_hex("CT:", ct_out, TEST_PT_LEN);
    print_hex("TAG:", tag_out, 16);

    uint8_t dec[TEST_PT_LEN + 1];
    size_t dec_len;
    st = psa_aead_decrypt(key, PSA_ALG_GCM,
                           TEST_NONCE, sizeof(TEST_NONCE),
                           NULL, 0,
                           output, out_len,
                           dec, sizeof(dec), &dec_len);
    dec[TEST_PT_LEN] = '\0';
    printk("  DEC:    %s\n", dec);
    printk("  verify: %s\n\n", st == PSA_SUCCESS ? "OK" : "FAIL");

    psa_destroy_key(key);
}

int main(void)
{
    timing_init();
    timing_start();

    printk("\n=== AES-256 GCM Benchmark ===\n\n");

    psa_crypto_init();

    /* ── correctness: same input, compare outputs ── */
    printk("--- Correctness (same key/nonce/pt) ---\n");
    printk("  PT: \"%.*s\"\n\n", (int)TEST_PT_LEN, TEST_PT);

    uint8_t our_ct[TEST_PT_LEN], our_tag[16];
    uint8_t psa_ct[TEST_PT_LEN], psa_tag[16];

    correctness_our_impl(our_ct, our_tag);
    correctness_psa(psa_ct, psa_tag);

    printk("[CT match]  %s\n",
           memcmp(our_ct,  psa_ct,  TEST_PT_LEN) == 0 ? "OK" : "MISMATCH");
    printk("[TAG match] %s\n\n",
           memcmp(our_tag, psa_tag, 16) == 0 ? "OK" : "MISMATCH");

    /* ── timing ── */
    printk("--- Timing ---\n\n");
    bench_gcm_all();

    timing_stop();
    return 0;
}
