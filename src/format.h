#ifndef FORMAT_H
#define FORMAT_H

#include <stdint.h>

// extractPubkeyBytes converts a Ledger-style public key to a Sia-friendly
// 32-byte array.
void extractPubkeyBytes(unsigned char *dst, const uint8_t publicKey[static 65]);

// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(char *dst, const uint8_t *data, uint64_t inlen);

// bin2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin2dec(char *dst, uint64_t n);

// formatSC converts a decimal string from Hastings to Siacoins. It returns the
// new length of the string.
int formatSC(char *buf, uint8_t decLen);

#endif /* FORMAT_H */