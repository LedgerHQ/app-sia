/*******************************************************************************
 *
 *  (c) 2016 Ledger
 *  (c) 2018 Nebulous
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <stdbool.h>
#include <stdint.h>
#include "main_std_app.h"
#include "offsets.h"
#include "os.h"
#include "os_io_seproxyhal.h"
#include "io.h"
#include "ux.h"
#include "parser.h"

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"

// These are global variables declared in ux.h. They can't be defined there
// because multiple files include ux.h; they need to be defined in exactly one
// place. See ux.h for their descriptions.
commandContext global;
const internalStorage_t N_storage_real;

void ui_idle(void);

static void update_blind_sign_ui(void);

static void toggle_blind_sign(void) {
    const bool new_value = !N_storage.blindSign;
    nvm_write((void *) &N_storage.blindSign, (void *) &new_value, sizeof(bool));
    update_blind_sign_ui();
}

static void controls_callback(int token, uint8_t index, int page);

#define SETTING_INFO_NB 2
static const char *const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer"};
static const char *const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, APPDEVELOPER};

// settings switches definitions
enum { BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN };
enum { BLIND_SIGNING_ID = 0, SETTINGS_SWITCHES_NB };

static nbgl_contentSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB,
     .content.switchesList.switches = switches,
     .contentActionCallback = controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

static void controls_callback(int token,
                              uint8_t index __attribute__((unused)),
                              int page __attribute__((unused))) {
    if (token == BLIND_SIGNING_TOKEN) {
        toggle_blind_sign();
    }
}

static void update_blind_sign_ui(void) {
    switches[BLIND_SIGNING_ID].initState = N_storage.blindSign ? ON_STATE : OFF_STATE;
}

void app_quit(void) {
    // exit app here
    app_exit();
}

void ui_idle(void) {
#ifdef SCREEN_SIZE_WALLET
    switches[BLIND_SIGNING_ID].text = "Enable blind signing";
    switches[BLIND_SIGNING_ID].subText = "Recommend only for experienced users";
#else
    switches[BLIND_SIGNING_ID].text = "Blind signing";
#endif
    switches[BLIND_SIGNING_ID].token = BLIND_SIGNING_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    switches[BLIND_SIGNING_ID].tuneId = TUNE_TAP_CASUAL;
#endif
    nbgl_useCaseHomeAndSettings(APPNAME,
#ifdef SCREEN_SIZE_WALLET
                                &ICON_APP_SIA,
                                NULL,
#else
                                NULL,
                                "Awaiting commands",
#endif
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_quit);
}

unsigned int io_reject(void) {
    io_send_sw(SW_USER_REJECTED);
    // Return to the main screen.
    ui_idle();
    return 0;
}

// This is the function signature for a command handler.
// Returns 0 on success.
typedef uint16_t handler_fn_t(uint8_t ins,
                              uint8_t p1,
                              uint8_t p2,
                              uint8_t *dataBuffer,
                              uint16_t dataLength);

handler_fn_t handleGetVersion;
handler_fn_t handleGetPublicKey;
handler_fn_t handleSignHash;
handler_fn_t handleCalcTxnHash;

static handler_fn_t *lookupHandler(uint8_t ins) {
    switch (ins) {
        case INS_GET_VERSION:
            return handleGetVersion;
        case INS_GET_PUBLIC_KEY:
            return handleGetPublicKey;
        case INS_SIGN_HASH:
            return handleSignHash;
        case INS_GET_TXN_HASH:
        case INS_GET_V2TXN_HASH:
            return handleCalcTxnHash;
        default:
            return NULL;
    }
}

static void send_error_code(uint16_t e) {
    // Convert the exception to a response code. All error codes
    // start with 6, except for 0x9000, which is a special
    // "success" code. Every APDU payload should end with such a
    // code, even if no other data is sent. For example, when
    // calcTxnHash is processing packets of txn data, it replies
    // with just 0x9000 to indicate that it is ready to receive
    // more data.
    //
    // If the first byte is not a 6, mask it with 0x6800 to
    // convert it to a proper error code. I'm not totally sure why
    // this is done; perhaps to handle single-byte exception
    // codes?
    short sw = 0;
    switch (e & 0xF000) {
        case 0x6000:
        case 0x9000:
            sw = e;
            break;
        default:
            sw = 0x6800 | (e & 0x7FF);
            break;
    }
    io_send_sw(sw);
}

void app_main() {
    // Mark the transaction context as uninitialized.
    explicit_bzero(&global, sizeof(global));

    // Initialize io
    io_init();

    if (!N_storage.initialized) {
        internalStorage_t storage = {0};
        storage.initialized = true;
        nvm_write((void *) &N_storage, (void *) &storage, sizeof(internalStorage_t));
    }
    update_blind_sign_ui();
    ui_idle();

    int input_len = 0;
    command_t cmd = {0};
    for (;;) {
        // Read command into G_io_apdu_buffer
        if ((input_len = io_recv_command()) < 0) {
            PRINTF("Failed to receive");
            io_send_sw(SW_INVALID_PARAM);
            continue;
        }

        // Parse command into CLA, INS, P1/P2, LC, and data
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            PRINTF("Invalid command length");
            io_send_sw(SW_INVALID_PARAM);
            continue;
        }

        // Lookup and call the requested command handler.
        handler_fn_t *handlerFn = lookupHandler(cmd.ins);
        if (!handlerFn) {
            PRINTF("Instruction not supported");
            send_error_code(SWO_INVALID_INS);
            continue;
        }

        const uint16_t e = handlerFn(cmd.ins, cmd.p1, cmd.p2, cmd.data, cmd.lc);
        if (e != 0) {
            send_error_code(e);
            continue;
        }
    }
}
