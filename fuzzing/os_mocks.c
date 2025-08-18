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
void assert_exit(bool confirm __attribute__((unused))) {
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

bolos_task_status_t os_sched_last_status(unsigned int task_idx __attribute__((unused))) {
    return 1;
}

size_t cx_hash_get_size(const cx_hash_t *ctx __attribute__((unused))) {
    return 32;
}

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash __attribute__((unused))) {
    return CX_OK;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash __attribute__((unused)),
                          uint32_t mode __attribute__((unused)),
                          const uint8_t *in __attribute__((unused)),
                          size_t len __attribute__((unused)),
                          uint8_t *out __attribute__((unused)),
                          size_t out_len __attribute__((unused))) {
    return CX_OK;
}

cx_err_t cx_blake2b_init_no_throw(cx_blake2b_t *hash __attribute__((unused)),
                                  size_t size __attribute__((unused))) {
    return CX_OK;
}

cx_err_t cx_eddsa_get_public_key_no_throw(const cx_ecfp_private_key_t *pv_key
                                          __attribute__((unused)),
                                          cx_md_t hashID __attribute__((unused)),
                                          cx_ecfp_public_key_t *pu_key __attribute__((unused)),
                                          uint8_t *a __attribute__((unused)),
                                          size_t a_len __attribute__((unused)),
                                          uint8_t *h __attribute__((unused)),
                                          size_t h_len __attribute__((unused))) {
    pu_key->W_len = 65;
    memset(pu_key, 'A', pu_key->W_len);
    return CX_OK;
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey __attribute__((unused)),
                                cx_md_t hashID __attribute__((unused)),
                                const uint8_t *hash __attribute__((unused)),
                                size_t hash_len __attribute__((unused)),
                                uint8_t *sig __attribute__((unused)),
                                size_t sig_len __attribute__((unused))) {
    return CX_OK;
}

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv __attribute__((unused)),
                                       size_t *length __attribute__((unused))) {
    // Sia uses CX_CURVE_Ed25519
    if (cv == CX_CURVE_Ed25519) {
        *length = 32;
        return CX_OK;
    }

    exit(1);
    return CX_INVALID_PARAMETER;
}

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve __attribute__((unused)),
                                           const uint8_t *rawkey __attribute__((unused)),
                                           size_t key_len __attribute__((unused)),
                                           cx_ecfp_private_key_t *pvkey __attribute__((unused))) {
    return CX_OK;
}

cx_err_t cx_ecdsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey __attribute__((unused)),
                                uint32_t mode __attribute__((unused)),
                                cx_md_t hashID __attribute__((unused)),
                                const uint8_t *hash __attribute__((unused)),
                                size_t hash_len __attribute__((unused)),
                                uint8_t *sig __attribute__((unused)),
                                size_t *sig_len __attribute__((unused)),
                                uint32_t *info __attribute__((unused))) {
    return CX_OK;
}

cx_err_t cx_ecfp_generate_pair2_no_throw(cx_curve_t curve __attribute__((unused)),
                                         cx_ecfp_public_key_t *public_key __attribute__((unused)),
                                         cx_ecfp_private_key_t *private_key __attribute__((unused)),
                                         bool keep_private __attribute__((unused)),
                                         cx_md_t hashID __attribute__((unused))) {
    return CX_OK;
}

void os_perso_derive_node_with_seed_key(unsigned int mode __attribute__((unused)),
                                        cx_curve_t curve __attribute__((unused)),
                                        const unsigned int *path __attribute__((unused)),
                                        unsigned int pathLength __attribute__((unused)),
                                        unsigned char *privateKey __attribute__((unused)),
                                        unsigned char *chain __attribute__((unused)),
                                        unsigned char *seed_key __attribute__((unused)),
                                        unsigned int seed_key_length __attribute__((unused))) {
}

cx_err_t cx_ecdsa_sign_rs_no_throw(const cx_ecfp_private_key_t *key __attribute__((unused)),
                                   uint32_t mode __attribute__((unused)),
                                   cx_md_t hashID __attribute__((unused)),
                                   const uint8_t *hash __attribute__((unused)),
                                   size_t hash_len __attribute__((unused)),
                                   size_t rs_size __attribute__((unused)),
                                   uint8_t *sig_r __attribute__((unused)),
                                   uint8_t *sig_s __attribute__((unused)),
                                   uint32_t *info __attribute__((unused))) {
    return CX_OK;
}
