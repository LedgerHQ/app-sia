#include "sia.h"

#include <cx.h>
#include <ledger_assert.h>
#include <lib_standard_app/crypto_helpers.h>
#include <os.h>
#include <os_seed.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "blake2b.h"
#include "format.h"

static void siaSetPath(uint32_t index, uint32_t path[static 5]) {
    path[0] = 44 | 0x80000000;
    path[1] = 93 | 0x80000000;
    path[2] = index | 0x80000000;
    path[3] = 0x80000000;
    path[4] = 0x80000000;
}

void deriveSiaPublicKey(uint32_t index, uint8_t publicKey[static 65]) {
    uint32_t bip32Path[5];
    siaSetPath(index, bip32Path);

    LEDGER_ASSERT(CX_OK == bip32_derive_with_seed_get_pubkey_256(HDW_ED25519_SLIP10,
                                                                 CX_CURVE_Ed25519,
                                                                 bip32Path,
                                                                 5,
                                                                 publicKey,
                                                                 NULL,
                                                                 CX_SHA512,
                                                                 NULL,
                                                                 0),
                  "get pubkey failed");
}

void deriveAndSign(uint8_t *dst, uint32_t index, const uint8_t *hash) {
    uint32_t bip32Path[5];
    siaSetPath(index, bip32Path);

    size_t signatureLength = 64;
    LEDGER_ASSERT(CX_OK == bip32_derive_with_seed_eddsa_sign_hash_256(HDW_ED25519_SLIP10,
                                                                      CX_CURVE_Ed25519,
                                                                      bip32Path,
                                                                      5,
                                                                      CX_SHA512,
                                                                      hash,
                                                                      32,
                                                                      dst,
                                                                      &signatureLength,
                                                                      NULL,
                                                                      0),
                  "signing txn failed");
}

void pubkeyToSiaAddress(char *dst, const uint8_t publicKey[static 65]) {
    // A Sia address is the Merkle root of a set of unlock conditions.
    // For a "standard" address, the unlock conditions are:
    //
    // - no timelock
    // - one public key
    // - one signature required
    //
    // For now, the Ledger will only be able to generate standard addresses.
    // We can add support for arbitrary unlock conditions later.

    // defined in RFC 6962
    const uint8_t leafHashPrefix = 0;
    const uint8_t nodeHashPrefix = 1;

    // encode the timelock, pubkey, and sigsrequired
    // TODO: can reuse buffers here to make this more efficient
    uint8_t timelockData[9];
    memset(timelockData, 0, sizeof(timelockData));
    timelockData[0] = leafHashPrefix;

    uint8_t pubkeyData[57];
    memset(pubkeyData, 0, sizeof(pubkeyData));
    pubkeyData[0] = leafHashPrefix;
    memmove(pubkeyData + 1, "ed25519", 7);
    pubkeyData[17] = 32;
    extractPubkeyBytes(pubkeyData + 25, publicKey);

    uint8_t sigsrequiredData[9];
    memset(sigsrequiredData, 0, sizeof(sigsrequiredData));
    sigsrequiredData[0] = leafHashPrefix;
    sigsrequiredData[1] = 1;

    // To calculate the Merkle root, we need a buffer large enough to hold two
    // hashes plus a special leading byte.
    uint8_t merkleData[65];
    merkleData[0] = nodeHashPrefix;
    // hash timelock into slot 1
    blake2b(merkleData + 1, 32, timelockData, sizeof(timelockData));
    // hash pubkey into slot 2
    blake2b(merkleData + 33, 32, pubkeyData, sizeof(pubkeyData));
    // join hashes into slot 1
    blake2b(merkleData + 1, 32, merkleData, 65);
    // hash sigsrequired into slot 2
    blake2b(merkleData + 33, 32, sigsrequiredData, sizeof(sigsrequiredData));
    // join hashes into slot 1, finishing Merkle root (unlock hash)
    blake2b(merkleData + 1, 32, merkleData, 65);

    // hash the unlock hash to get a checksum
    uint8_t checksum[6];
    blake2b(checksum, sizeof(checksum), merkleData + 1, 32);

    // convert the hash+checksum to hex
    bin2hex(dst, merkleData + 1, 32);
    bin2hex(dst + 64, checksum, sizeof(checksum));
}
