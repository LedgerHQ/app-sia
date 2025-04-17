#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <cmocka.h>
#include "format.h"

static void test_bin2hex(void **state) {
    (void) state;

    const uint8_t src[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 255};
    char dst[2 * sizeof(src) + 1];
    bin2hex(dst, src, sizeof(src));

    const char expected[2 * sizeof(src) + 1] = {
        '0', '0', '0', '1', '0', '2', '0', '4', '0', '8',  '1',
        '0', '2', '0', '4', '0', '8', '0', 'f', 'f', '\0',
    };
    assert_memory_equal(expected, dst, sizeof(expected));
}

static void test_extractPubkeyBytes(void **state) {
    (void) state;

    uint8_t pubkey[65] = {0};
    for (int i = 0; i < 65; i++) {
        pubkey[i] = i;
    }
    pubkey[32] = 1;

    unsigned char dst[32];
    extractPubkeyBytes(dst, pubkey);

    for (int i = 0; i < 31; i++) {
        assert_int_equal(dst[i], pubkey[64 - i]);
    }
    assert_true(dst[31] & 0x80);
}

static void test_bin2dec_zero(void **state) {
    (void) state;

    char buf[32];
    int len = bin2dec(buf, 0);

    assert_int_equal(len, 1);
    assert_string_equal(buf, "0");
}

static void test_bin2dec_large(void **state) {
    (void) state;

    char buf[32];
    int len = bin2dec(buf, 1234567890ULL);

    assert_int_equal(len, 10);
    assert_string_equal(buf, "1234567890");
}

static void test_formatSC_zero(void **state) {
    (void) state;

    char buf[255] = {0};
    buf[0] = '0';
    const int len = formatSC(buf, 1);

    // Should result in: "0 SC"
    assert_int_equal(len, 1 + 1 + 2);
    assert_string_equal(buf, "0 SC");
}

static void test_formatSC_small(void **state) {
    (void) state;

    char buf[255] = {0};
    buf[0] = '0';
    buf[1] = '1';
    buf[2] = '2';
    buf[3] = '3';
    const int len = formatSC(buf, 4);

    // Should result in: "0.000000000000000000000123 SC"
    assert_int_equal(len, 26 + 1 + 2);
    assert_string_equal(buf, "0.000000000000000000000123 SC");
}

static void test_formatSC_large(void **state) {
    (void) state;

    char buf[255] = {0};
    buf[0] = '1';
    for (int i = 1; i < 26; i++) {
        buf[i] = '7';
    }
    const int len = formatSC(buf, 26);

    // Should result in: "17.777777777777777777777777 SC"
    assert_int_equal(len, 27 + 1 + 2);
    assert_string_equal(buf, "17.777777777777777777777777 SC");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bin2hex),
        cmocka_unit_test(test_extractPubkeyBytes),
        cmocka_unit_test(test_bin2dec_zero),
        cmocka_unit_test(test_bin2dec_large),
        cmocka_unit_test(test_formatSC_zero),
        cmocka_unit_test(test_formatSC_small),
        cmocka_unit_test(test_formatSC_large),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
