from ragger.backend import BackendInterface, RaisePolicy
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavIns, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)


test_to_sign = bytes.fromhex(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def __toggle_setting(firmware: Firmware, navigator: Navigator) -> None:
    if firmware.is_nano:
        navigator.navigate([
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
        ], screen_change_before_first_instruction=False)
    else:
        navigator.navigate([
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, (350,115)),
            NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
        ], screen_change_before_first_instruction=False)



# Test will ask to sign a hash that will be accepted on screen
def test_sign_hash_accept(firmware: Firmware,
                          backend: BackendInterface,
                          navigator: Navigator,
                          scenario_navigator: NavigateWithScenario):
    client = BoilerplateCommandSender(backend)
    index = 5

    __toggle_setting(firmware, navigator)

    with client.sign_hash_with_confirmation(index, test_to_sign):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        scenario_navigator.review_approve()

    response = client.get_async_response()
    assert response.status == Errors.SW_OK
    assert response.data == bytes.fromhex(
        "abd9187ca30200709137fa76dee32d58700f05c2debef62fb9b36af663498657384772ea437c886e07be20ddc60aaf04bb54736ab5dbaed4c00a6bdffcf7750f"
    )


# Test will ask to sign a hash that will be rejected on screen
def test_sign_hash_reject(firmware: Firmware,
                          backend: BackendInterface,
                          navigator: Navigator,
                          scenario_navigator: NavigateWithScenario):
    client = BoilerplateCommandSender(backend)
    index = 5

    __toggle_setting(firmware, navigator)

    with client.sign_hash_with_confirmation(index, test_to_sign):
        # Disable raising when trying to unpack an error APDU
        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        scenario_navigator.review_reject()

    # Assert that we have received a refusal
    response = client.get_async_response()
    assert response.status == Errors.SW_DENY
    assert len(response.data) == 0
