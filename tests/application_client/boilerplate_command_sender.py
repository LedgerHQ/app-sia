from enum import IntEnum
from typing import Generator, List, Optional
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU


MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    P1_MORE = 0x80


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80

    P2_DISPLAY_ADDRESS = 0x00
    P2_DISPLAY_PUBKEY = 0x01

    P2_DISPLAY_HASH = 0x00
    P2_SIGN_HASH = 0x01


class InsType(IntEnum):
    GET_VERSION = 0x01
    GET_PUBLIC_KEY = 0x02
    SIGN_HASH = 0x04
    GET_TXN_HASH = 0x08


class Errors(IntEnum):
    SW_OK = 0x9000
    SW_INVALID_PARAM = 0x6B01

    SW_DENY = 0x6985
    SW_WRONG_P1P2 = 0x6A86
    SW_WRONG_DATA_LENGTH = 0x6A87
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL = 0xB002
    SW_DISPLAY_AMOUNT_FAIL = 0xB003
    SW_WRONG_TX_LENGTH = 0xB004
    SW_TX_PARSING_FAIL = 0xB005
    SW_TX_HASH_FAIL = 0xB006
    SW_BAD_STATE = 0xB007
    SW_SIGNATURE_FAIL = 0xB008


def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


class BoilerplateCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=0xB0,  # specific CLA for BOLOS
            ins=0x01,  # specific INS for get_app_and_version
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=b"",
        )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_START, p2=P2.P2_LAST, data=b""
        )

    @contextmanager
    def get_address_with_confirmation(self, index: int) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_DISPLAY_ADDRESS,
            data=index.to_bytes(4, "little", signed=False),
        ) as response:
            yield response

    @contextmanager
    def get_public_key_with_confirmation(
        self, index: int
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_DISPLAY_PUBKEY,
            data=index.to_bytes(4, "little", signed=False),
        ) as response:
            yield response

    @contextmanager
    def sign_hash_with_confirmation(
        self, index: int, to_sign: bytes
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.SIGN_HASH,
            p1=P1.P1_START,
            p2=P2.P2_DISPLAY_PUBKEY,
            data=index.to_bytes(4, "little", signed=False) + to_sign[:32],
        ) as response:
            yield response

    @contextmanager
    def sign_tx(
        self,
        key_index: int,
        sig_index: int,
        change_index: int,
        transaction: bytes,
    ) -> Generator[None, None, None]:
        p1 = P1.P1_START
        messages = split_message(
            key_index.to_bytes(4, "little", signed=False)
            + sig_index.to_bytes(2, "little", signed=False)
            + change_index.to_bytes(4, "little", signed=False)
            + transaction,
            MAX_APDU_LEN,
        )
        for i in range(len(messages) - 1):
            with self.backend.exchange_async(
                cla=CLA,
                ins=InsType.GET_TXN_HASH,
                p1=p1,
                p2=P2.P2_SIGN_HASH,
                data=messages[i],
            ) as response:
                pass
            p1 = P1.P1_MORE

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_TXN_HASH,
            p1=p1,
            p2=P2.P2_SIGN_HASH,
            data=messages[-1],
        ) as response:
            yield response

    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
