# project information
project(TxParser
        VERSION 1.0
        DESCRIPTION "Transaction parser of Boilerplate app"
        LANGUAGES C)

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG
    "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra -Wno-unused-function -DFUZZ -pedantic -g -O0"
)

add_compile_definitions(
    IO_HID_EP_LENGTH=64
    HAVE_ECC
    HAVE_ECC_WEIERSTRASS
    HAVE_SECP_CURVES
    HAVE_ECC_TWISTED_EDWARDS
    HAVE_ED_CURVES
    HAVE_ECDSA
    HAVE_EDDSA
    HAVE_HASH
    HAVE_BLAKE2
    HAVE_SHA224
    HAVE_SHA256
    HAVE_SHA3
    HAVE_SHA512
)

add_library(txparser
    ${BOLOS_SDK}/src/ledger_assert.c

    ${BOLOS_SDK}/lib_standard_app/format.c
    ${BOLOS_SDK}/lib_standard_app/bip32.c
    ${BOLOS_SDK}/lib_standard_app/crypto_helpers.c

    # cxng
    ${BOLOS_SDK}/lib_cxng/src/cx_hash.c
    ${BOLOS_SDK}/lib_cxng/src/cx_sha256.c
    ${BOLOS_SDK}/lib_cxng/src/cx_sha512.c
    ${BOLOS_SDK}/lib_cxng/src/cx_sha3.c
    ${BOLOS_SDK}/lib_cxng/src/cx_utils.c
    ${BOLOS_SDK}/lib_cxng/src/cx_ram.c

    ${CMAKE_CURRENT_SOURCE_DIR}/../src/blake2b.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sia_format.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/sia.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/txn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/v2txn.c
)

set_target_properties(txparser PROPERTIES SOVERSION 1)

target_include_directories(txparser PUBLIC
    ${BOLOS_SDK}
    ${BOLOS_SDK}/include
    ${BOLOS_SDK}/lib_standard_app
    ${BOLOS_SDK}/lib_cxng/include
    ${BOLOS_SDK}/lib_cxng/src
    ${BOLOS_SDK}/target/nanox/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
