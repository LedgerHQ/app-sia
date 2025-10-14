#pragma once

#include <stdint.h>

// extractPubkeyBytes converts a Ledger-style public key to a Sia-friendly
// 32-byte array.
void extractPubkeyBytes(unsigned char *dst, const uint8_t publicKey[static 65]);

// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(char *dst, size_t dstLen, const uint8_t *data, size_t dataLen);

// bin2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin2dec(char *dst, size_t dstLen, uint64_t n);

// formatSC converts a decimal string from Hastings to Siacoins. It returns the
// new length of the string.
int formatSC(char *buf, size_t bufLen, uint8_t decLen);
