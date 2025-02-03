#ifndef HAVE_BAGL

#include <io.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ux.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"
#include "txn.h"
#include "nbgl_use_case.h"

static calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

static void confirm_callback(bool confirm) {
    ctx->initialized = false;

    if (confirm) {
        if (ctx->sign) {
            uint8_t signature[64] = {0};
            deriveAndSign(signature, ctx->keyIndex, ctx->txn.sigHash);
            io_send_response_pointer(signature, sizeof(signature), SW_OK);
            nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
        } else {
            io_send_response_pointer(ctx->txn.sigHash, sizeof(ctx->txn.sigHash), SW_OK);
            nbgl_useCaseStatus("TRANSACTION HASHED", true, ui_idle);
        }
    } else {
        io_send_sw(SW_USER_REJECTED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

static nbgl_contentTagValue_t *getTagValuePairs(uint8_t pairIndex) {
    static nbgl_contentTagValue_t contentTagValue = {0};
    txn_state_t *txn = &ctx->txn;
    uint8_t valLen = 0;

    switch (txn->elements[ctx->elementIndex].elemType) {
        case TXN_ELEM_SC_OUTPUT:
            // For each siacoin output, the user needs to see both
            // the destination address and the amount.
            ctx->elementIndex = pairIndex / 2;
            if (pairIndex % 2 == 0) {
                format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
                contentTagValue.item = "To";
                contentTagValue.value = ctx->fullStr[0];
            } else {
                valLen = cur2dec(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal);
                formatSC(ctx->fullStr[1], valLen);
                contentTagValue.item = "Amount (SC)";
                contentTagValue.value = ctx->fullStr[1];
            }
            break;

        case TXN_ELEM_SF_OUTPUT:
            // For each siacoin output, the user needs to see both
            // the destination address and the amount.
            ctx->elementIndex = pairIndex / 2;
            if (pairIndex % 2 == 0) {
                format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
                contentTagValue.item = "To";
                contentTagValue.value = ctx->fullStr[0];
            } else {
                cur2dec(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal);
                contentTagValue.item = "Amount (SF)";
                contentTagValue.value = ctx->fullStr[1];
            }
            break;

        case TXN_ELEM_MINER_FEE:
            ctx->elementIndex = pairIndex;
            valLen = cur2dec(ctx->fullStr[0], txn->elements[ctx->elementIndex].outVal);
            formatSC(ctx->fullStr[0], valLen);
            contentTagValue.item = "Miner Fee Amount (SC)";
            contentTagValue.value = ctx->fullStr[0];
            break;

        default:
            // This should never happen.
            io_send_sw(SW_DEVELOPER_ERR);
            ui_idle();
            break;
    }

    return &contentTagValue;
}

static void zero_ctx(void) {
    explicit_bzero(ctx, sizeof(calcTxnHashContext_t));
}

// handleCalcTxnHash reads a signature index and a transaction, calculates the
// SigHash of the transaction, and optionally signs the hash using a specified
// key. The transaction is displayed piece-wise to the user.
uint16_t handleCalcTxnHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength) {
    nbgl_contentTagValueList_t contentTagValueList = {0};
    uint16_t i = 0;

    if ((p1 != P1_FIRST && p1 != P1_MORE) || (p2 != P2_DISPLAY_HASH && p2 != P2_SIGN_HASH)) {
        return SW_INVALID_PARAM;
    }

    if (p1 == P1_FIRST) {
        // If this is the first packet of a transaction, the transaction
        // context must not already be initialized. (Otherwise, an attacker
        // could fool the user by concatenating two transactions.)
        //
        // NOTE: ctx->initialized is set to false when the Sia app loads.
        if (ctx->initialized) {
            zero_ctx();
            return SW_IMPROPER_INIT;
        }
        explicit_bzero(ctx, sizeof(calcTxnHashContext_t));
        ctx->initialized = true;

        // If this is the first packet, it will include the key index, sig
        // index, and change index in addition to the transaction data. Use
        // these to initialize the ctx and the transaction decoder.
        ctx->keyIndex = U4LE(dataBuffer, 0);  // NOTE: ignored if !ctx->sign
        dataBuffer += 4;
        dataLength -= 4;
        uint16_t sigIndex = U2LE(dataBuffer, 0);
        dataBuffer += 2;
        dataLength -= 2;
        uint32_t changeIndex = U4LE(dataBuffer, 0);
        dataBuffer += 4;
        dataLength -= 4;
        txn_init(&ctx->txn, sigIndex, changeIndex);

        // Set ctx->sign according to P2.
        ctx->sign = (p2 & P2_SIGN_HASH);

        ctx->elemPart = 0;
    } else {
        // If this is not P1_FIRST, the transaction must have been
        // initialized previously.
        if (!ctx->initialized) {
            zero_ctx();
            return SW_IMPROPER_INIT;
        }
    }

    // Add the new data to transaction decoder.
    txn_update(&ctx->txn, dataBuffer, dataLength);

    switch (txn_parse(&ctx->txn)) {
        case TXN_STATE_ERR:
            // don't leave state lingering
            zero_ctx();
            return SW_INVALID_PARAM;
            break;
        case TXN_STATE_PARTIAL:
            return SW_OK;
            break;
        case TXN_STATE_FINISHED:
            // Computes the number of pairs to display
            contentTagValueList.nbPairs = 0;
            for (i = 0; i < ctx->txn.elementIndex; i++) {
                contentTagValueList.nbPairs +=
                    (ctx->txn.elements[i].elemType == TXN_ELEM_MINER_FEE) ? 1 : 2;
            }
            contentTagValueList.callback = getTagValuePairs;
            nbgl_useCaseReview(TYPE_TRANSACTION,
                               &contentTagValueList,
                               &C_stax_app_sia_big,
                               (ctx->sign) ? "Sign Transaction" : "Hash Transaction",
                               NULL,
                               (ctx->sign) ? "Sign Transaction" : "Hash Transaction",
                               confirm_callback);
            break;
    }

    return 0;
}

#endif /* HAVE_BAGL */
