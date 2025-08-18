#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "v2txn.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    txn_state_t txn = {0};
    v2txn_init(&txn, 0, 0);

    for (size_t i = 0; i < size; i += sizeof(txn.buf)) {
        const uint8_t read_size = MIN(0xFF, size - i);
        v2txn_update(&txn, data + i, read_size);

        const txnDecoderState_e result = v2txn_parse(&txn);
        if (result == TXN_STATE_ERR) {
            // if we encounter this error in the app, we zero the transaction
            // context and don't continue
            return 0;
        }
    }

    return 0;
}
