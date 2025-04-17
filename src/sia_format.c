#include "format.h"

#include <string.h>

void extractPubkeyBytes(unsigned char *dst, const uint8_t publicKey[static 65]) {
    for (int i = 0; i < 32; i++) {
        dst[i] = publicKey[64 - i];
    }
    if (publicKey[32] & 1) {
        dst[31] |= 0x80;
    }
}

void bin2hex(char *dst, const uint8_t *data, uint64_t inlen) {
    static uint8_t const hex[] = "0123456789abcdef";
    for (uint64_t i = 0; i < inlen; i++) {
        dst[2 * i + 0] = hex[(data[i] >> 4) & 0x0F];
        dst[2 * i + 1] = hex[(data[i] >> 0) & 0x0F];
    }
    dst[2 * inlen] = '\0';
}

int bin2dec(char *dst, uint64_t n) {
    if (n == 0) {
        dst[0] = '0';
        dst[1] = '\0';
        return 1;
    }
    // determine final length
    int len = 0;
    for (uint64_t nn = n; nn != 0; nn /= 10) {
        len++;
    }
    // write digits in big-endian order
    for (int i = len - 1; i >= 0; i--) {
        dst[i] = (n % 10) + '0';
        n /= 10;
    }
    dst[len] = '\0';
    return len;
}

#define SC_ZEROS 24

int formatSC(char *buf, uint8_t decLen) {
    if (decLen < SC_ZEROS + 1) {
        // if < 1 SC, pad with leading zeros
        memmove(buf + (SC_ZEROS - decLen) + 2, buf, decLen + 1);
        memset(buf, '0', SC_ZEROS + 2 - decLen);
        decLen = SC_ZEROS + 1;
    } else {
        memmove(buf + (decLen - SC_ZEROS) + 1, buf + (decLen - SC_ZEROS), SC_ZEROS + 1);
    }
    // add decimal point, trim trailing zeros, and add units
    buf[decLen - SC_ZEROS] = '.';
    while (decLen > 0 && buf[decLen] == '0') {
        decLen--;
    }
    if (buf[decLen] == '.') {
        decLen--;
    }
    memmove(buf + decLen + 1, " SC", 4);
    return decLen + 4;
}
