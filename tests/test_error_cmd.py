from ragger.backend import BackendInterface
from ragger.backend import RaisePolicy

from application_client.boilerplate_command_sender import CLA, Errors


# Ensure the app returns an error when a bad INS is used
def test_bad_ins(backend: BackendInterface):
    # Disable raising when trying to unpack an error APDU
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    rapdu = backend.exchange(cla=CLA, ins=0xFF)
    assert rapdu.status == Errors.SW_INS_NOT_SUPPORTED
