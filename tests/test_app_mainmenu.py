from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID

from utils import ROOT_SCREENSHOT_PATH


# In this test we check the behavior of the device main menu
def test_app_mainmenu(firmware: Firmware, navigator: Navigator, test_name: str):
    # Navigate in the main menu
    if firmware.is_nano:
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_INFO,
            NavInsID.USE_CASE_SETTINGS_NEXT,
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT,
        ]
    navigator.navigate_and_compare(
        ROOT_SCREENSHOT_PATH,
        test_name,
        instructions,
        screen_change_before_first_instruction=False,
    )
