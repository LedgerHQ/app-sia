#include <stdlib.h>
#include "os.h"
#include "cx.h"
#include "ux.h"
#include "cx_hash.h"
#include "lcx_sha256.h"

size_t strlcat(char *dst, const char *src, size_t Size) {
    size_t ld = strlen(dst);
    size_t ls = strlen(src);
    if (ld >= Size) return 0;
    if (ld + ls >= Size) ls = Size - ld - 1;
    strncat(dst, src, ls);
    return ld + ls;
}

// ignore so we don't crash when failin to generate key for change address
// because we mock everything
void assert_exit(bool confirm) {
    // exit(-1);
}

void os_longjmp(unsigned int exception) {
    longjmp(try_context_get()->jmp_buf, exception);
}

try_context_t *current_context = NULL;
try_context_t *try_context_get(void) {
    return current_context;
}

try_context_t *try_context_set(try_context_t *ctx) {
    try_context_t *previous_ctx = current_context;
    current_context = ctx;
    return previous_ctx;
}

bolos_task_status_t os_sched_last_status(unsigned int task_idx) {
    return 1;
}

size_t cx_hash_get_size(const cx_hash_t *ctx) {
    return 32;
}

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    return CX_OK;
}

cx_err_t cx_hash_no_throw(
    cx_hash_t *hash, uint32_t mode, const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    return CX_OK;
}

cx_err_t cx_blake2b_init_no_throw(cx_blake2b_t *hash, size_t size) {
    return CX_OK;
}

cx_err_t cx_eddsa_get_public_key_no_throw(const cx_ecfp_private_key_t *pv_key,
                                          cx_md_t hashID,
                                          cx_ecfp_public_key_t *pu_key,
                                          uint8_t *a,
                                          size_t a_len,
                                          uint8_t *h,
                                          size_t h_len) {
    pu_key->W_len = 65;
    memset(pu_key, 'A', pu_key->W_len);
    return CX_OK;
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t sig_len) {
    return CX_OK;
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length) {
    // Sia uses CX_CURVE_Ed25519
    if (cv == CX_CURVE_Ed25519) {
        *length = 32;
        return CX_OK;
    }

    exit(1);
    return CX_INVALID_PARAMETER;
}

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve,
                                           const uint8_t *rawkey,
                                           size_t key_len,
                                           cx_ecfp_private_key_t *pvkey) {
    return CX_OK;
}

cx_err_t cx_ecdsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                uint32_t mode,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig,
                                size_t *sig_len,
                                uint32_t *info) {
    return CX_OK;
}

cx_err_t cx_ecfp_generate_pair2_no_throw(cx_curve_t curve,
                                         cx_ecfp_public_key_t *public_key,
                                         cx_ecfp_private_key_t *private_key,
                                         bool keep_private,
                                         cx_md_t hashID) {
    return CX_OK;
}

void os_perso_derive_node_with_seed_key(unsigned int mode,
                                        cx_curve_t curve,
                                        const unsigned int *path,
                                        unsigned int pathLength,
                                        unsigned char *privateKey,
                                        unsigned char *chain,
                                        unsigned char *seed_key,
                                        unsigned int seed_key_length) {
}

cx_err_t cx_ecdsa_sign_rs_no_throw(const cx_ecfp_private_key_t *key,
                                   uint32_t mode,
                                   cx_md_t hashID,
                                   const uint8_t *hash,
                                   size_t hash_len,
                                   size_t rs_size,
                                   uint8_t *sig_r,
                                   uint8_t *sig_s,
                                   uint32_t *info) {
    return CX_OK;
}