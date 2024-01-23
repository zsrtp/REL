#!/usr/bin/python3

"""Tool to pack/unpack Wii saves & inject REL modules."""

# Copyright 2021 kipcode66 & Seeky
# Based off of Dolphin Emulator Project https://github.com/dolphin-emu/dolphin.git
# Copyright 2010 Dolphin Emulator Project
# SPDX-License-Identifier: GPL-2.0-or-later

# Based off of tachtig/twintig http://git.infradead.org/?p=users/segher/wii.git
# See also: https://wiibrew.org/wiki/Segher%27s_Wii.git
# Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
# Licensed under the terms of the GNU GPL, version 2
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

# The binary data loaded in the save files is taken from the REL loader code from PistonMiner.
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2020 Linus S. (aka PistonMiner)
# Modifications made by Zephiles

import logging
import sys
import os
import argparse
import struct
import ctypes
from io import FileIO
from enum import IntEnum
from typing import Any, ByteString, Dict, List
from Crypto.Cipher import AES
import hashlib
import secrets
import json
import base64
from datetime import datetime

# +----------------------+
# | Constants definition |
# +----------------------+

# Program Constants/global varibables
VERSION = "0.2.1"

# Constants
BLOCK_SZ = 0x40
BNR_SZ = 0x60a0
ICON_SZ = 0x1200
FULL_BNR_MIN = 0x72a0  # BNR_SZ + 1*ICON_SZ
FULL_BNR_MAX = 0xF0A0  # BNR_SZ + 8*ICON_SZ
BK_LISTED_SZ = 0x70
SIG_SZ = 0x40
FULL_CERT_SZ = 0x3C0

DEFAULT_DEVICE_ID = 0x0403AC68

OS_BUS_CLOCK = 243000000

# Crypto values
SD_KEY = bytes([0xab, 0x01, 0xb9, 0xd8,
                0xe1, 0x62, 0x2b, 0x08,
                0xaf, 0xba, 0xd8, 0x4d,
                0xbf, 0xc2, 0xa5, 0x5d])
SD_INITIAL_IV = bytes([0x21, 0x67, 0x12, 0xE6,
                       0xAA, 0x1F, 0x68, 0x9F,
                       0x95, 0xC5, 0xA2, 0x23,
                       0x24, 0xDC, 0x6A, 0x98])
MD5_BLANKER = bytes([0x0E, 0x65, 0x37, 0x81,
                     0x99, 0xBE, 0x45, 0x17,
                     0xAB, 0x06, 0xEC, 0x22,
                     0x45, 0x1A, 0x57, 0x93])
NG_ID = 0x0403AC68
CA_ID = 1
MS_ID = 2

DEFAULT_KEY_ID = 0x6AAB8C59

SYSTEM_MENU = 0x0000000100000002

DEFAULT_SIGNATURE = bytes([
    # R
    0x00, 0xD8, 0x81, 0x63, 0xB2, 0x00, 0x6B, 0x0B, 0x54, 0x82,
    0x88, 0x63, 0x81, 0x1C, 0x00, 0x71, 0x12, 0xED, 0xB7, 0xFD,
    0x21, 0xAB, 0x0E, 0x50, 0x0E, 0x1F, 0xBF, 0x78, 0xAD, 0x37,
    # S
    0x00, 0x71, 0x8D, 0x82, 0x41, 0xEE, 0x45, 0x11, 0xC7, 0x3B,
    0xAC, 0x08, 0xB6, 0x83, 0xDC, 0x05, 0xB8, 0xA8, 0x90, 0x1F,
    0xA8, 0x2A, 0x0E, 0x4E, 0x76, 0xEF, 0x44, 0x72, 0x99, 0xF8
])

DEFAULT_PRIVATE_KEY = bytes([0x00, 0xAB, 0xEE, 0xC1, 0xDD, 0xB4,
                             0xA6, 0x16, 0x6B, 0x70, 0xFD, 0x7E,
                             0x56, 0x67, 0x70, 0x57, 0x55, 0x27,
                             0x38, 0xA3, 0x26, 0xC5, 0x46, 0x16,
                             0xF7, 0x62, 0xC9, 0xED, 0x73, 0xF2])

# DEFAULT_PUBLIC_KEY = ec.privToPub(commondefs.DEFAULT_PRIVATE_KEY)
DEFAULT_PUBLIC_KEY = bytes([0x01, 0x04, 0x0b, 0xe0, 0x46, 0xea,
                            0x95, 0x19, 0xf2, 0x85, 0x9b, 0x0d,
                            0x94, 0x29, 0xa2, 0xc6, 0x91, 0x80,
                            0x15, 0x89, 0x8f, 0x2e, 0xba, 0x20,
                            0xcf, 0xfd, 0xb3, 0x16, 0x4f, 0x0c,
                            0x01, 0x38, 0xc5, 0xd2, 0x2f, 0xc1,
                            0xe9, 0xee, 0x17, 0x6c, 0x2d, 0x8f,
                            0xa4, 0x74, 0xb0, 0xe9, 0x38, 0x66,
                            0x6e, 0x60, 0xcf, 0x06, 0xd5, 0x08,
                            0x7a, 0xc2, 0x4f, 0x01, 0x39, 0x79])

SQUARE = bytes([0x00, 0x01, 0x04, 0x05,
                0x10, 0x11, 0x14, 0x15,
                0x40, 0x41, 0x44, 0x45,
                0x50, 0x51, 0x54, 0x55])

SIGNATURE_END_MAGIC = 0x2f536969

# ACE data

TIDS = {0x00010000525a4445: "us0",
        0x00010000525a4450: "eu", 0x00010000525a444a: "jp"}

VERSIONS = {"us0": 0x00010000525a4445, "us2": 0x00010000525a4445,
            "eu": 0x00010000525a4450, "jp": 0x00010000525a444a}

GAME_INFO_PTR = {
    # NA 1.0
    "us0": 0x80492928,
    # NA 1.2
    "us2": 0x80479F30,
    # PAL
    "eu": 0x8047A828,
    # JP
    "jp": 0x80477DB0,
}

BIN_DATA_INIT = {
    # NA 1.0
    "us0": base64.b64decode("PICASYiEOEAchAqUOIQCCDyggEZgpYPgfYUiFH2JA6ZOgAQg"),
    # NA 1.2
    "us2": base64.b64decode("PICASIiErkgchAqUOIQCCDyggERgpfngfYUiFH2JA6ZOgAQg"),
    # PAL
    "eu":  base64.b64decode("PICASIiEt0AchAqUOIQCCDyggEVgpQLgfYUiFH2JA6ZOgAQg"),
    # JP
    "jp":  base64.b64decode("PICASIiEjMgchAqUOIQCCDyggERgpdhgfYUiFH2JA6ZOgAQg"),
}

BIN_DATA_MAIN = {
    '1': {
        # NA 1.0
        "us0": base64.b64decode("PGCANGBjxXRIAAAFfIgCpjiEAFBIAAFJiG2yYCwDAABBg"
                                "gAggG27SDiAAAU4oAABPYCAKmGM/Nx9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKn4fYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAvo9gIA8YYwJFH2IA6ZOgAAhf6PreDiAAvpIAADRk"
                                "62/kDh9AvqQbb+UPGCANGBjd/RjpADsSAAAnTxggDRgbM"
                                "V4fYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4R28Hx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAL6S4wH9WPDW/Q4gAL6SAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIA0YGPFdDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CANGOlYYh8"
                                "qAOmToAAIWOjYmx8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbJklCH/4HwIAqaQAQAkv2EACD"
                                "/ggAA7wAAAOIAAjEgAALV8fRt4Y+Ne5H+k63g4oAABSDb"
                                "BZSwDAABAggDEOIAAIEgAAJF8ext4f6PreH9k23g4oAAg"
                                "SDa5ASwDAABBgACQg5sAADucAB9XnAA0f2TbeEgAAFl/h"
                                "ON4SAAAWXx7G3h/o+t4f2TbeH+F43hINrjJLAMAAEGAAF"
                                "iAmwAgSAAANXx8G3h/Y9t4f4TjeEg0UZksAwABQIIAKJO"
                                "fVLiTf1S8g9sANEgAADCAbbNkSC3XvIBts2Q4oAAgSC3R"
                                "JH9j23hINFOxf4TjeEv//+F/ZNt4S///2X+j63hINsJxf"
                                "6TreEv//8ksHgAAQYIADH/IA6ZOgAAhu2EACIABACR8CA"
                                "OmOCEAIEgAJ2g="),  # 706372656C2E62696E00
        # NA 1.2
        "us2": base64.b64decode("PGCAM2Bjb0RIAAAFfIgCpjiEAFBIAAFJiG2x4CwDAABBg"
                                "gAggG266DiAAAU4oAABPYCAKmGM9vB9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKqwfYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAvo9gIA6YYyzTH2IA6ZOgAAhf6PreDiAAvpIAADRk"
                                "62/CDh9AvqQbb8MPGCAM2BjIcRjpADsSAAAnTxggDNgbG"
                                "9IfYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4MgwHx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAL6S4qyLWPDW/Q4gAL6SAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIAzYGNvRDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CAM2OlC1h8"
                                "qAOmToAAIWOjDDx8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbHklCH/4HwIAqaQAQAkv2EACD"
                                "/ggAA7wAAAOIAAjEgAALV8fRt4Y+Ne5H+k63g4oAABSDV"
                                "rnSwDAABAggDEOIAAIEgAAJF8ext4f6PreH9k23g4oAAg"
                                "SDVjOSwDAABBgACQg5sAADucAB9XnAA0f2TbeEgAAFl/h"
                                "ON4SAAAWXx7G3h/o+t4f2TbeH+F43hINWMBLAMAAEGAAF"
                                "iAmwAgSAAANXx8G3h/Y9t4f4TjeEgy+2ksAwABQIIAKJO"
                                "fVLiTf1S8g9sANEgAADCAbbLkSCyBjIBtsuQ4oAAgSCx6"
                                "9H9j23hIMv2Bf4TjeEv//+F/ZNt4S///2X+j63hINWypf"
                                "6TreEv//8ksHgAAQYIADH/IA6ZOgAAhu2EACIABACR8CA"
                                "OmOCEAIEgAJ2g="),  # 706372656C2E62696E00
        # PAL
        "eu":  base64.b64decode("PGCAM2Bjc3RIAAAFfIgCpjiEAFBIAAFJiG2woCwDAABBg"
                                "gAggG25qDiAAAU4oAABPYCAKmGM+yB9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKqgfYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAvo9gIA6YYy30H2IA6ZOgAAhf6PreDiAAvpIAADRk"
                                "629yDh9AvqQbb3MPGCAM2BjJfRjpADsSAAAnTxggDNgbH"
                                "N4fYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4Mk8Hx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAL6S4q2sWPDW/Q4gAL6SAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIAzYGNzdDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CAM2OlD4h8"
                                "qAOmToAAIWOjEGx8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbCklCH/4HwIAqaQAQAkv2EACD"
                                "/ggAA7wAAAOIAAjEgAALV8fRt4Y+Ne5H+k63g4oAABSDV"
                                "vzSwDAABAggDEOIAAIEgAAJF8ext4f6PreH9k23g4oAAg"
                                "SDVnaSwDAABBgACQg5sAADucAB9XnAA0f2TbeEgAAFl/h"
                                "ON4SAAAWXx7G3h/o+t4f2TbeH+F43hINWcxLAMAAEGAAF"
                                "iAmwAgSAAANXx8G3h/Y9t4f4TjeEgy/5ksAwABQIIAKJO"
                                "fVLiTf1S8g9sANEgAADCAbbGkSCyFvIBtsaQ4oAAgSCx/"
                                "JH9j23hIMwGxf4TjeEv//+F/ZNt4S///2X+j63hINXDZf"
                                "6TreEv//8ksHgAAQYIADH/IA6ZOgAAhu2EACIABACR8CA"
                                "OmOCEAIEgAJ2g="),  # 706372656C2E62696E00
        # JP
        "jp":  base64.b64decode("PGCAM2BjimRIAAAFfIgCpjiEAFBIAAFJiG2x4CwDAABBg"
                                "gAggG262DiAAAU4oAABPYCAK2GMEhB9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKssfYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAvo9gIA6YYzOBH2IA6ZOgAAhf6PreDiAAvpIAADRk"
                                "62++Dh9AvqQbb78PGCAM2BjPORjpADsSAAAnTxggDNgbI"
                                "pofYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4M74Hx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAL6S4rM5WPDW/Q4gAL6SAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIAzYGOKZDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CAM2OlJnh8"
                                "qAOmToAAIWOjJ1x8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbHklCH/4HwIAqaQAQAkv2EACD"
                                "/ggAA7wAAAOIAAjEgAALV8fRt4Y+Ne5H+k63g4oAABSDW"
                                "GVSwDAABAggDEOIAAIEgAAJF8ext4f6PreH9k23g4oAAg"
                                "SDV98SwDAABBgACQg5sAADucAB9XnAA0f2TbeEgAAFl/h"
                                "ON4SAAAWXx7G3h/o+t4f2TbeH+F43hINX25LAMAAEGAAF"
                                "iAmwAgSAAANXx8G3h/Y9t4f4TjeEgzFoksAwABQIIAKJO"
                                "fVLiTf1S8g9sANEgAADCAbbLkSCycrIBtsuQ4oAAgSCyW"
                                "FH9j23hIMxihf4TjeEv//+F/ZNt4S///2X+j63hINYdhf"
                                "6TreEv//8ksHgAAQYIADH/IA6ZOgAAhu2EACIABACR8CA"
                                "OmOCEAIEgAJ2g="),  # 706372656C2E62696E00
    },
    '2': {
        # NA 1.0
        "us0": base64.b64decode("PGCANGBjxXRIAAAFfIgCpjiEAFBIAAFJiG2yYCwDAABBg"
                                "gAggG27SDiAAAU4oAABPYCAKmGM/Nx9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKn4fYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAw49gIA8YYwJFH2IA6ZOgAAhf6PreDiAAw5IAADRk"
                                "62/kDh9Aw6Qbb+UPGCANGBjd/RjpADsSAAAnTxggDRgbM"
                                "V4fYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4R28Hx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAMOS4wH9WPDW/Q4gAMOSAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIA0YGPFdDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CANGOlYYh8"
                                "qAOmToAAIWOjYmx8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbJklCH/UHwIAqaQAQC0v2EACD"
                                "/ggAA7wAAAO6EAIGPjXvh/pOt4OKAAAUg2wW0sAwAAQII"
                                "A+IBts2Q4gAAgOKAAIEgt0b18ext4f6PreH9k23g4oAAg"
                                "SDa5ASwDAABAgQCog5sAADucAB9XnAA0gG2zZH9k23hIL"
                                "dgVgG2zZH+E43g4oAAgSC3ReXx7G3h/o+t4f2TbeH+F43"
                                "hINri9LAMAAECBAGSAbbNsgJsAIIC7AERILdFNfHwbeH9"
                                "j23h/hON4SDRRjSwDAAFAggAogLsASHy7KFCAbbNkf2Tb"
                                "eEgt2ZGTn1S4k39UvIPbADRIAAAkf2PbeEg0U52AbbNsf"
                                "4TjeEgt14mAbbNkf2TbeEgt131/o+t4SDbCVSweAABBgg"
                                "AMf8gDpk6AACG7YQAIgAEAtHwIA6Y4IQCwSAAnVA=="),
        # NA 1.2
        "us2": base64.b64decode("PGCAM2Bjb0RIAAAFfIgCpjiEAFBIAAFJiG2x4CwDAABBg"
                                "gAggG266DiAAAU4oAABPYCAKmGM9vB9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKqwfYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAw49gIA6YYyzTH2IA6ZOgAAhf6PreDiAAw5IAADRk"
                                "62/CDh9Aw6Qbb8MPGCAM2BjIcRjpADsSAAAnTxggDNgbG"
                                "9IfYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4MgwHx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAMOS4qyLWPDW/Q4gAMOSAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIAzYGNvRDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CAM2OlC1h8"
                                "qAOmToAAIWOjDDx8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbHklCH/UHwIAqaQAQC0v2EACD"
                                "/ggAA7wAAAO6EAIGPjXvh/pOt4OKAAAUg1a6UsAwAAQII"
                                "A+IBtsuQ4gAAgOKAAIEgse418ext4f6PreH9k23g4oAAg"
                                "SDVjOSwDAABAgQCog5sAADucAB9XnAA0gG2y5H9k23hIL"
                                "IHlgG2y5H+E43g4oAAgSCx7SXx7G3h/o+t4f2TbeH+F43"
                                "hINWL1LAMAAECBAGSAbbLsgJsAIIC7AERILHsdfHwbeH9"
                                "j23h/hON4SDL7XSwDAAFAggAogLsASHy7KFCAbbLkf2Tb"
                                "eEgsg2GTn1S4k39UvIPbADRIAAAkf2PbeEgy/W2AbbLsf"
                                "4TjeEgsgVmAbbLkf2TbeEgsgU1/o+t4SDVsjSweAABBgg"
                                "AMf8gDpk6AACG7YQAIgAEAtHwIA6Y4IQCwSAAnVA=="),
        # PAL
        "eu":  base64.b64decode("PGCAM2Bjc3RIAAAFfIgCpjiEAFBIAAFJiG2woCwDAABBg"
                                "gAggG25qDiAAAU4oAABPYCAKmGM+yB9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKqgfYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAw49gIA6YYy30H2IA6ZOgAAhf6PreDiAAw5IAADRk"
                                "629yDh9Aw6Qbb3MPGCAM2BjJfRjpADsSAAAnTxggDNgbH"
                                "N4fYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4Mk8Hx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAMOS4q2sWPDW/Q4gAMOSAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIAzYGNzdDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CAM2OlD4h8"
                                "qAOmToAAIWOjEGx8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbCklCH/UHwIAqaQAQC0v2EACD"
                                "/ggAA7wAAAO6EAIGPjXvh/pOt4OKAAAUg1b9UsAwAAQII"
                                "A+IBtsaQ4gAAgOKAAIEgsf718ext4f6PreH9k23g4oAAg"
                                "SDVnaSwDAABAgQCog5sAADucAB9XnAA0gG2xpH9k23hIL"
                                "IYVgG2xpH+E43g4oAAgSCx/eXx7G3h/o+t4f2TbeH+F43"
                                "hINWclLAMAAECBAGSAbbGsgJsAIIC7AERILH9NfHwbeH9"
                                "j23h/hON4SDL/jSwDAAFAggAogLsASHy7KFCAbbGkf2Tb"
                                "eEgsh5GTn1S4k39UvIPbADRIAAAkf2PbeEgzAZ2AbbGsf"
                                "4TjeEgshYmAbbGkf2TbeEgshX1/o+t4SDVwvSweAABBgg"
                                "AMf8gDpk6AACG7YQAIgAEAtHwIA6Y4IQCwSAAnVA=="),
        # JP
        "jp":  base64.b64decode("PGCAM2BjimRIAAAFfIgCpjiEAFBIAAFJiG2x4CwDAABBg"
                                "gAggG262DiAAAU4oAABPYCAK2GMEhB9iAOmToAAIThgAA"
                                "A8gIAAOKAAAD2AgAFhjKssfYkDpk6ABCCUIf/gfAgCppA"
                                "BACS/oQAIfH4beHyfI3g/oICwf6PreEgAAAV8iAKmOIT/"
                                "gDigAw49gIA6YYzOBH2IA6ZOgAAhf6PreDiAAw5IAADRk"
                                "62++Dh9Aw6Qbb78PGCAM2BjPORjpADsSAAAnTxggDNgbI"
                                "pofYkDpn/D83h/5Pt4u6EACIABACR8CAOmOCEAIE6ABCB"
                                "8fxt4PGCBM2BjOpw8gICwYIQBDEgAAF1/4/t4S4M74Hx/"
                                "G3g/wIAAY8Nb9DyAgLA4oAMOS4rM5WPDW/Q4gAMOSAAAS"
                                "TxggABgY4ZEY8RduEgAACE8YIAzYGOKZDyAgABghFxQSA"
                                "AADX/j+3hIgzlIfIMgUFSEAbo8oEgAfKUjeJCjAAA4gAA"
                                "ElCH/4HwIAqaQAQAkv6EACHx/G3h8niN4P6CAM2OlJnh8"
                                "qAOmToAAIWOjJ1x8aAOmf+P7eH/E83hOgAAhu6EACIABA"
                                "CR8CAOmOCEAIE6AACCQbbHklCH/UHwIAqaQAQC0v2EACD"
                                "/ggAA7wAAAO6EAIGPjXvh/pOt4OKAAAUg1hl0sAwAAQII"
                                "A+IBtsuQ4gAAgOKAAIEgslq18ext4f6PreH9k23g4oAAg"
                                "SDV98SwDAABAgQCog5sAADucAB9XnAA0gG2y5H9k23hIL"
                                "J0FgG2y5H+E43g4oAAgSCyWaXx7G3h/o+t4f2TbeH+F43"
                                "hINX2tLAMAAECBAGSAbbLsgJsAIIC7AERILJY9fHwbeH9"
                                "j23h/hON4SDMWfSwDAAFAggAogLsASHy7KFCAbbLkf2Tb"
                                "eEgsnoGTn1S4k39UvIPbADRIAAAkf2PbeEgzGI2AbbLsf"
                                "4TjeEgsnHmAbbLkf2TbeEgsnG1/o+t4SDWHRSweAABBgg"
                                "AMf8gDpk6AACG7YQAIgAEAtHwIA6Y4IQCwSAAnVA=="),
    }
}

# +------------------+
# | Common functions |
# +------------------+


def alignUp(value: int, size: int):
    """Aligns and address to the given size.

    :param value: The address to align up.
    :type value: int
    :param size: The size to which we align the address.
    :type size: int

    :return The aligned address.
    :rtype int
    """
    return value + (size - value % size) % size


def sha1(data: bytes) -> bytes:
    hasher = hashlib.sha1()
    hasher.update(data)
    return hasher.digest()


def md5(data: bytes) -> bytes:
    hasher = hashlib.md5()
    hasher.update(data)
    return hasher.digest()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

# +-------------------+
# | Class definitions |
# +-------------------+

# Classes used to generate a new signature
# (Algorithm from the Dolphin Emulator project)


class Elt:
    pass


class Elt:
    __slots__ = ('data',)

    def __init__(self, data: bytes = bytes(30)):
        self.data = bytes(data[0:min(30, len(data))]) + \
            bytes(max(0, 30 - len(data)))

    def is_zero(self):
        return all(d == 0 for d in self.data)

    def mulX(self):
        new_data = bytearray(self.data)
        carry = new_data[0] & 1

        # x = (self.data[29] << 1) & 0xFF
        # xs = itertools.chain([0], ((y << 1) & 0xFF for y in self.data[1:-1]))
        # new_data[:-1] = list((x ^ (y >> 7)) & 0xFF for x, y in zip(xs, self.data[1:]))
        x = 0
        for i in range(29):
            y = new_data[i + 1]
            new_data[i] = (x ^ (y >> 7)) & 0xFF
            x = (y << 1) & 0xFF

        new_data[29] = (x ^ carry) & 0xFF
        new_data[20] ^= (carry << 2) & 0xFF
        self.data = bytes(new_data)

    def square(self):
        # wide = bytearray(y for x in (
        #     (SQUARE[x >> 4], SQUARE[x & 0xF]) for x in self.data) for y in x)
        wide = bytearray(60)
        for i in range(30):
            wide[2 * i] = SQUARE[self.data[i] >> 4]
            wide[2 * i + 1] = SQUARE[self.data[i] & 0xF]

        for i in range(30):
            x = wide[i]
            wide[i + 19] ^= x >> 7
            wide[i + 20] ^= (x << 1) & 0xFF
            wide[i + 29] ^= x >> 1
            wide[i + 30] ^= (x << 7) & 0xFF
        x = wide[30] & ~1
        wide[49] ^= x >> 7
        wide[50] ^= (x << 1) & 0xFF
        wide[59] ^= x >> 1
        wide[30] &= 1
        return Elt(wide[30:])

    def ItohTsujii(self, b, j):
        t = Elt(self.data)
        for _ in range(j):
            t = t.square()
        return t * b

    def inv(self):
        t = self.ItohTsujii(self, 1)
        s = t.ItohTsujii(self, 1)
        t = s.ItohTsujii(s, 3)
        s = t.ItohTsujii(self, 1)
        t = s.ItohTsujii(s, 7)
        s = t.ItohTsujii(t, 14)
        t = s.ItohTsujii(self, 1)
        s = t.ItohTsujii(t, 29)
        t = s.ItohTsujii(s, 58)
        s = t.ItohTsujii(t, 116)
        return s.square()

    def __add__(self, other):
        if not isinstance(other, Elt):
            raise TypeError(
                f"Cannot add {self.__class__.__name__} "
                f"with {other.__class__.__name__}")
        return Elt(bytes(a ^ b for a, b in zip(self.data, other.data)))

    def __truediv__(self, other):
        if not isinstance(other, Elt):
            raise TypeError(
                f"Cannot divide {self.__class__.__name__} "
                f"with {other.__class__.__name__}")
        return self * other.inv()

    def __mul__(self, other: Elt):
        if not isinstance(other, Elt):
            raise TypeError(
                f"Cannot multiply {self.__class__.__name__} "
                f"with {other.__class__.__name__}")
        d = Elt()
        i = 0
        mask = 1
        for _ in range(233):
            d.mulX()
            if (self.data[i] & mask) != 0:
                d = d + other
            mask >>= 1
            if mask == 0:
                mask = 0x80
                i += 1
        return d


class Point:
    __slots__ = ('x', 'y',)

    def __init__(self, x: Elt = Elt(), y: Elt = Elt()):
        self.x = Elt(x.data)
        self.y = Elt(y.data)

    def is_zero(self):
        return self.x.is_zero() and self.y.is_zero()

    def double(self):
        r = Point()
        if self.x.is_zero():
            return r
        s = (self.y / self.x)
        # print(s.data.hex())
        s = s + self.x
        r.x = s.square() + s
        r_x_data = bytearray(r.x.data)
        r_x_data[29] ^= 1
        r.x.data = bytes(r_x_data)
        r.y = s * r.x + r.x + self.x.square()
        return r

    def __add__(self, other):
        if not isinstance(other, Point):
            raise TypeError(
                f"Cannot add {self.__class__.__name__} "
                f"with {other.__class__.__name__}")
        if self.is_zero():
            return Point(other.x, other.y)
        if other.is_zero():
            return Point(self.x, self.y)
        u = self.x + other.x
        if u.is_zero():
            u = self.y + other.y
            if u.is_zero():
                return self.double()
            return Point()
        s = (self.y + other.y) / u
        t = s.square() + s + other.x
        t_data = bytearray(t.data)
        t_data[29] ^= 1
        t.data = bytes(t_data)
        rx = t + self.x
        ry = s * t + self.y + rx
        return Point(rx, ry)

    def __mul__(self, other):
        if not isinstance(other, ByteString):
            raise TypeError(
                f"Point only multiplies with bytes, "
                f"got {other.__class__.__name__}")
        d = Point()
        for i in range(30):
            mask = 0x80
            while mask != 0:
                d = d.double()
                if (other[i] & mask) != 0:
                    d = d + self
                mask >>= 1
        return d


EC_G = Point(Elt(bytes([0x00, 0xfa, 0xc9, 0xdf, 0xcb, 0xac,
                        0x83, 0x13, 0xbb, 0x21, 0x39, 0xf1,
                        0xbb, 0x75, 0x5f, 0xef, 0x65, 0xbc,
                        0x39, 0x1f, 0x8b, 0x36, 0xf8, 0xf8,
                        0xeb, 0x73, 0x71, 0xfd, 0x55, 0x8b])),
             Elt(bytes([0x01, 0x00, 0x6a, 0x08, 0xa4, 0x19,
                        0x03, 0x35, 0x06, 0x78, 0xe5, 0x85,
                        0x28, 0xbe, 0xbf, 0x8a, 0x0b, 0xef,
                        0xf8, 0x67, 0xa7, 0xca, 0x36, 0x71,
                        0x6f, 0x7e, 0x01, 0xf8, 0x10, 0x52])))

EC_N = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xe9, 0x74, 0xe7, 0x2f,
              0x8a, 0x69, 0x22, 0x03, 0x1d, 0x26, 0x03, 0xcf, 0xe0, 0xd7])


class SignatureType(IntEnum):
    RSA4096 = 0x00010000
    RSA2048 = 0x00010001
    ECC = 0x00010002


class PublicKeyType(IntEnum):
    RSA4096 = 0x00000000
    RSA2048 = 0x00000001
    ECC = 0x00000002


class SignatureECC:
    __slots__ = ('type', 'sig', 'fill', 'issuer',)
    PACK_FORMAT = struct.Struct('>I60s64s64s')

    def __init__(self, type: SignatureType, sig, fill, issuer):
        self.type = type
        self.sig = sig
        self.fill = fill
        self.issuer = issuer

    def pack(self):
        return SignatureECC.PACK_FORMAT.pack(self.type.value, self.sig, self.fill, self.issuer)


class CertHeader:
    __slots__ = ('public_key_type', 'name', 'id',)
    PACK_FORMAT = struct.Struct('>I64sI')

    def __init__(self, public_key_type: PublicKeyType, name, id):
        self.public_key_type = public_key_type
        self.name = name
        self.id = id

    def pack(self):
        return CertHeader.PACK_FORMAT.pack(self.public_key_type.value, self.name, self.id)


class CertECC:
    __slots__ = ("signature", "header", "public_key", "padding",)

    def __init__(self, signature: SignatureECC, header: CertHeader, public_key: bytes, padding: bytes):
        self.signature = signature
        self.header = header
        self.public_key = public_key
        self.padding = padding

    def pack(self):
        return self.signature.pack() + self.header.pack() + self.public_key + self.padding

# +---------------------+
# | Signature functions |
# +---------------------+


def priv_to_pub(key: bytes):
    data = EC_G * bytes(key)
    return data.x.data + data.y.data


def make_blank_ecc_cert(issuer, name, public_key: bytes, key_id):
    return CertECC(SignatureECC(SignatureType.ECC, bytes(60), bytes(0x40), bytes(issuer, 'utf-8')[0:min(0x3F, len(issuer))] + b'\0'), CertHeader(PublicKeyType.ECC, bytes(name, 'utf-8')[0:min(0x3F, len(name))] + b'\0', key_id), public_key, bytes(60))


def get_device_certificate(device_id=DEFAULT_DEVICE_ID):
    name = f"NG{device_id:08x}"
    cert = make_blank_ecc_cert(
        f"Root-CA{CA_ID:08x}-MS{MS_ID:08x}", name, DEFAULT_PUBLIC_KEY, DEFAULT_KEY_ID)
    cert.signature.sig = DEFAULT_SIGNATURE
    return cert


def bn_sub_modulus(a, N, n):
    a = bytearray(a)
    c = 0
    for i in range(n - 1, -1, -1):
        dig = N[i] + c
        c = a[i] < dig
        a[i] = (a[i] - dig) & 0xFF
    return a


def bn_add(a: bytes, b: bytes, N, n):
    d = bytearray(n)
    c = 0
    for i in range(n - 1, -1, -1):
        dig = a[i] + b[i] + c
        c = (dig >= 0x100)
        d[i] = (dig) & 0xFF

    if c:
        d = bn_sub_modulus(d, N, n)
    if d >= N:
        d = bn_sub_modulus(d, N, n)
    return d


def bn_mul(a, b, N, n):
    d = bytearray(n)
    for i in range(n):
        mask = 0x80
        while mask != 0:
            d = bn_add(d, d, N, n)
            if (a[i] & mask) != 0:
                d = bn_add(d, b, N, n)
            mask >>= 1
    return d


def bn_exp(a, N, n, e, en):
    t = bytearray(512)
    d = bytearray(n)
    d[n - 1] = 1
    for i in range(en):
        mask = 0x80
        while mask != 0:
            t = bn_mul(d, d, N, n)
            if (e[i] & mask) != 0:
                d = bn_mul(t, a, N, n)
            else:
                d[:] = t[:n]
            mask >>= 1
    return d


def bn_inv(a, N, n):
    d = bytearray(n)
    t = bytearray(512)
    s = bytearray(512)
    t[0:n] = N
    s[n - 1] = 2
    t = bn_sub_modulus(t, s, n)
    d = bn_exp(a, N, n, t, n)
    return d


def sign2(key: bytes, hash: bytes):
    e = bytearray(30)
    e[10:] = hash
    m = bytearray(secrets.token_bytes(30))
    m[0] &= 1
    while m >= EC_N:
        m = bytearray(secrets.token_bytes(30))
        m[0] &= 1
    r = (EC_G * m).x
    if r.data >= EC_N:
        r.data = bytes(bn_sub_modulus(r.data, EC_N, 30))

    kk = bytearray(30)
    kk[:] = key
    if kk >= EC_N:
        kk = bn_sub_modulus(kk, EC_N, 30)
    s = Elt(bn_mul(r.data, kk, EC_N, 30))
    kk = bn_add(s.data, e, EC_N, 30)
    minv = bn_inv(m, EC_N, 30)
    s.data = bytes(bn_mul(minv, kk, EC_N, 30))

    signature = bytearray(60)
    signature[:30] = r.data
    signature[30:] = s.data
    return bytes(signature)


def sign(title_id, data, device_id=DEFAULT_DEVICE_ID):
    hash = bytearray(20)
    ap_priv = bytearray(30)
    ap_priv[0x1d] = 1

    logging.debug(f"Signing for device #{device_id:08x}")
    # In practice, we can reduce the encryption time by using a
    # pre-calculated "cert", but it's not a significant amount of time
    signer = f"Root-CA{CA_ID:08x}-MS{MS_ID:08x}-NG{device_id:08x}"
    name = f"AP{title_id:016x}"
    logging.debug("Creating certificate...")
    cert = make_blank_ecc_cert(signer, name, priv_to_pub(ap_priv), 0)
    cert_packed = cert.pack()
    hash = sha1(cert_packed[0x80:])
    cert.signature.sig = sign2(DEFAULT_PRIVATE_KEY, hash)
    cert = cert.pack()

    logging.debug("Signing data...")
    hash = sha1(data)
    signature = sign2(ap_priv, hash)
    logging.debug("Signed")

    return (signature, cert)


def verify_signature(public_key, signature, hash):
    r = signature[:30]
    s = signature[30:]

    s_inv = bn_inv(s, EC_N, 30)
    e = bytearray(30)
    e[10:] = hash[:20]

    w1 = bn_mul(e, s_inv, EC_N, 30)
    w2 = bn_mul(r, s_inv, EC_N, 30)

    public_key_point = Point(Elt(public_key[:30]), Elt(public_key[30:]))
    r1 = EC_G * w1 + public_key_point * w2
    rx = r1.x.data
    if rx >= EC_N:
        rx = bn_sub_modulus(rx, EC_N, 30)

    return rx == r


class Header:
    """The encryption header.

    It contains the necessary data for the save file's encryption and
    signature. It wraps the archive that contains the game's saved
    files.
    """

    __slots__ = ("tid", "banner_size", "permissions",
                 "unk1", "md5", "unk2", "banner",)
    PACK_FORMAT = struct.Struct('>QIBB16sH')
    PACK_SIZE = PACK_FORMAT.size + FULL_BNR_MAX

    def __init__(self, tid: int, banner_size: int, permissions: int, unk1: int, md5: bytes, unk2: int, banner=bytes()):
        self.tid = tid
        self.banner_size = banner_size
        self.permissions = permissions
        self.unk1 = unk1
        self.md5 = md5
        self.unk2 = unk2
        self.banner = banner

    def __repr__(self) -> str:
        return (f"Header(tid=0x{self.tid:016x}, "
                f"banner_size=0x{self.banner_size:08x}, "
                f"permissions=0x{self.permissions:02x}, "
                f"unk1=0x{self.unk1:02x}, "
                f"md5=0x{self.md5.hex()}, "
                f"unk2={self.unk2:04x}, "
                f"banner={self.banner})")

    def __str__(self) -> str:
        return (f"Header(tid=0x{self.tid:016x}, "
                f"banner_size=0x{self.banner_size:08x}, "
                f"permissions=0x{self.permissions:02x}, "
                f"unk1=0x{self.unk1:02x}, "
                f"md5=0x{self.md5.hex()}, "
                f"unk2={self.unk2:04x}, "
                f"banner={self.banner.__class__.__name__}({len(self.banner)}))")

    def updateBanner(self, banner: bytes):
        """Updates the headers and sets the new banner.

        :param banner: The banner file
        :type banner: bytes
        """
        new_size = len(banner)
        if (new_size < FULL_BNR_MIN) or (new_size > FULL_BNR_MAX) or (((new_size - BNR_SZ) % ICON_SZ) != 0):
            logging.error(f"Invalid banner size {new_size:04x}")
        self.banner_size = new_size
        self.banner = banner
        self.md5 = md5(self.to_bytes())

    @staticmethod
    def generate(banner: bytes, game_version: str):
        """Generates a new header from a given banner for the given version
        of 'The Legend of Zelda: Twilight Princess'.
        """
        hdr = Header(VERSIONS[game_version], len(
            banner), 0x34, 0, MD5_BLANKER, 0, banner)
        hdr.md5 = md5(hdr.to_bytes())
        return hdr

    @staticmethod
    def unpack(buffer: bytes):
        data = aes_cbc_decrypt(SD_KEY, SD_INITIAL_IV,
                               buffer[0:Header.PACK_SIZE])
        hdr = Header(
            *Header.PACK_FORMAT.unpack(data[0:Header.PACK_FORMAT.size]))
        hdr.banner = data[Header.PACK_FORMAT.size:][0:hdr.banner_size]
        if (hdr.banner_size < FULL_BNR_MIN) or (hdr.banner_size > FULL_BNR_MAX) or (((hdr.banner_size - BNR_SZ) % ICON_SZ) != 0):
            logging.error(
                "Warning: Not a Wii save or read failure for "
                f"banner size 0x{hdr.banner_size:04x} ({hdr.banner_size})")
            return
        hdr_md5 = hdr.md5
        hdr.md5 = MD5_BLANKER
        md5_calc = md5(hdr.to_bytes())
        hdr.md5 = hdr_md5
        if md5_calc != hdr_md5:
            logging.error(
                f"[Header] MD5 mismatch: {hdr_md5.hex()} != {md5_calc.hex()}")
            return
        return hdr

    @staticmethod
    def from_file(reader: FileIO):
        reader.seek(0)
        return Header.unpack(reader.read(Header.PACK_SIZE))

    def to_bytes(self):
        data1 = Header.PACK_FORMAT.pack(
            self.tid, self.banner_size, self.permissions, self.unk1, self.md5, self.unk2)
        data2 = self.banner
        if len(data2) < FULL_BNR_MAX:
            data2 += bytes(FULL_BNR_MAX - self.banner_size)
        return data1 + data2

    def pack(self):
        self.md5 = MD5_BLANKER
        self.md5 = md5(self.to_bytes())
        return aes_cbc_encrypt(SD_KEY, SD_INITIAL_IV, self.to_bytes())


class BkHeader:
    """The archive header.

    This header contains the data related to the archival of
    the files saved by the game.
    """

    __slots__ = ("size", "magic", "ngid", "number_of_files", "size_of_files",
                 "unk1", "unk2", "total_size", "unk3", "tid", "mac_address",
                 "padding",)
    PACK_FORMAT = struct.Struct('>8I64sQ6s18s')
    MAGIC = 0x426B0001

    def __init__(self, size, magic, ngid, number_of_files, size_of_files, unk1, unk2, total_size, unk3, tid, mac_address, padding):
        self.size = size
        self.magic = magic
        self.ngid = ngid
        self.number_of_files = number_of_files
        self.size_of_files = size_of_files
        self.unk1 = unk1
        self.unk2 = unk2
        self.total_size = total_size
        self.unk3 = unk3
        self.tid = tid
        self.mac_address = mac_address
        self.padding = padding

    def __repr__(self) -> str:
        return f"BkHeader(size=0x{self.size:08x}, magic=0x{self.magic:08x}, ngid=0x{self.ngid:08x}, number_of_files={self.number_of_files}, size_of_files={self.size_of_files}, unk1={self.unk1}, unk2={self.unk2}, total_size={self.total_size}, unk3={self.unk3}, tid=0x{self.tid:016x}, mac_address={self.mac_address}, padding={self.padding})"

    def __str__(self) -> str:
        return f"BkHeader(size=0x{self.size:08x}, magic=0x{self.magic:08x}, ngid=0x{self.ngid:08x}, number_of_files={self.number_of_files}, size_of_files={self.size_of_files}, unk1={self.unk1}, unk2={self.unk2}, total_size={self.total_size}, unk3={self.unk3.__class__.__name__}({len(self.unk3)}), tid=0x{self.tid:016x}, mac_address={self.mac_address.hex()}, padding={self.padding.__class__.__name__}({len(self.padding)}))"

    @staticmethod
    def generate(files: list, game_version: str):
        size_of_files = sum(len(file) for file in files)
        bkh = BkHeader(BK_LISTED_SZ, BkHeader.MAGIC, DEFAULT_DEVICE_ID, len(files), size_of_files, 0, 0,
                       size_of_files + FULL_CERT_SZ, bytes(0x40), VERSIONS[game_version], bytes(6), bytes(0x12))
        return bkh

    @staticmethod
    def unpack(buffer):
        hdr = BkHeader(*BkHeader.PACK_FORMAT.unpack(buffer))
        if hdr.size != BK_LISTED_SZ:
            logging.error(
                f"[BkHeader] Invalid header size: {BK_LISTED_SZ} != {hdr.size}")
            return
        if hdr.magic != BkHeader.MAGIC:
            logging.error(
                f"[BkHeader] Magic mismatch: {BkHeader.MAGIC:08x} != {hdr.magic:08x}")
            return
        if hdr.size_of_files + FULL_CERT_SZ != hdr.total_size:
            logging.error(
                f"[BkHeader] Invalid files size: {hdr.size_of_files + FULL_CERT_SZ} != {hdr.total_size}")
            return
        return hdr

    @staticmethod
    def from_file(reader: FileIO):
        reader.seek(Header.PACK_SIZE)
        data = reader.read(BkHeader.PACK_FORMAT.size)
        return BkHeader.unpack(data)

    def to_bytes(self):
        return BkHeader.PACK_FORMAT.pack(self.size, self.magic, self.ngid, self.number_of_files, self.size_of_files, self.unk1, self.unk2, self.total_size, self.unk3, self.tid, self.mac_address, self.padding)

    def pack(self):
        return self.to_bytes()


class NodeType(IntEnum):
    FILE = 1
    DIR = 2


class FileHDR:
    __slots__ = ("magic", "size", "permissions", "attrib",
                 "node_type", "name", "padding", "iv", "unk",)
    PACK_FORMAT = struct.Struct('>II3B64s5s16s32s')
    MAGIC = 0x03adf17e

    def __init__(self, magic, size, permissions, attrib, node_type: NodeType, name, padding, iv, unk):
        self.magic = magic
        self.size = size
        self.permissions = permissions
        self.attrib = attrib
        self.node_type = NodeType(node_type)
        self.name = name
        self.padding = padding
        self.iv = iv
        self.unk = unk

    def __str__(self) -> str:
        return f"FileHDR(magic=0x{self.magic:08x}, size=0x{self.size:08x}, permissions=0x{self.permissions:02x}, attrib=0x{self.attrib:02x}, node_type={self.node_type.name[:1].upper() + self.node_type.name.lower()[1:]}, name={self.name}, padding=bytes({len(self.padding)}), iv={self.iv.hex()}, unk={self.unk})"

    @staticmethod
    def unpack(buffer):
        file_hdr = FileHDR(*FileHDR.PACK_FORMAT.unpack(buffer))
        if file_hdr.magic != FileHDR.MAGIC:
            logging.error(
                f"[FileHDR] magic field mismatch: {FileHDR.MAGIC:08x} != {file_hdr.magic:08x}")
            return
        return file_hdr

    @staticmethod
    def from_save_file(save):
        if len(save.path) >= 0x40:
            logging.error(
                f"Error: file name {save.path!a} is too long (64 characters max)")
            return
        file_hdr = FileHDR(FileHDR.MAGIC, len(save.data) if save.node_type == 1 else 0, save.mode,
                           save.attributes, save.node_type, bytes(save.path, 'utf-8')[:min(0x40, len(save.path))] + bytes(max(0, 0x40-len(save.path))), bytes(5), SD_INITIAL_IV, bytes(0x20))
        return file_hdr

    def pack(self):
        return FileHDR.PACK_FORMAT.pack(self.magic, self.size, self.permissions, self.attrib, self.node_type, self.name, self.padding, self.iv, self.unk)


class SaveFile:
    def __init__(self, mode=0, attributes=0, node_type: NodeType = NodeType.DIR, path="", data=None):
        self.mode = mode
        self.attributes = attributes
        self.node_type = NodeType(node_type)
        self.path = path
        self.data = data

    def __repr__(self) -> str:
        return f"SaveFile(path={repr(self.path)}, node_type={self.node_type}, mode={self.mode}, attributes={self.attributes}, data={self.data})"

    def __str__(self) -> str:
        return f"SaveFile(path=\"{self.path}\", node_type={self.node_type.name[:1].upper() + self.node_type.name.lower()[1:]}, mode={self.mode}, attributes={self.attributes}, data={self.data.__class__.__name__}({len(self.data)}))"

    @staticmethod
    def unpack(reader: FileIO):
        data = reader.read(FileHDR.PACK_FORMAT.size)
        file_hdr = FileHDR.unpack(data)
        if file_hdr is None:
            return
        file_data = None
        if file_hdr.node_type == NodeType.FILE:
            size = file_hdr.size
            rounded_size = alignUp(size, BLOCK_SZ)
            file_data = reader.read(rounded_size)
            file_data = aes_cbc_decrypt(SD_KEY, file_hdr.iv, file_data)[0:size]
        return SaveFile(file_hdr.permissions, file_hdr.attrib, file_hdr.node_type,
                        file_hdr.name.split(b'\x00')[0].decode('utf-8'), file_data)

    @staticmethod
    def unpack_all(reader: FileIO, bkh: BkHeader):
        files: List[SaveFile] = []
        reader.seek(Header.PACK_SIZE + BkHeader.PACK_FORMAT.size)
        for i in range(0, bkh.number_of_files):
            logging.debug(f"[SaveFile] Unpacking file #{i}")
            file = SaveFile.unpack(reader)
            if not file is None:
                files.append(file)
            else:
                logging.error(f"[SaveFile] Error while unpacking file #{i}")
                return
        return files

    def pack(self):
        file_hdr = FileHDR.from_save_file(self)
        if file_hdr is None:
            return
        data_enc = bytes(0)
        if not self.data is None and len(self.data) > 0:
            data_aligned = self.data + \
                bytes(alignUp(len(self.data), BLOCK_SZ) - len(self.data))
            data_enc = aes_cbc_encrypt(SD_KEY, file_hdr.iv, data_aligned)
        return file_hdr.pack() + data_enc

    def metadata(self):
        return {'path': self.path, 'mode': self.mode, 'attributes': self.attributes, 'type': self.node_type}

    @staticmethod
    def pack_all(files):
        data = bytes()
        for file in files:
            data = data + file.pack()
        return data

    def __len__(self):
        return FileHDR.PACK_FORMAT.size + alignUp(len(self.data), BLOCK_SZ) if self.node_type == 1 else 0


class SaveBin:
    def __init__(self, header: Header, bkheader: BkHeader, files: List[SaveFile]):
        self.header = header
        self.bkheader = bkheader
        self.files = files

    def __repr__(self) -> str:
        return f"SaveBin(header={repr(self.header)}, bkheader={repr(self.bkheader)}, files=[{', '.join([repr(file) for file in self.files])}])"

    def __str__(self) -> str:
        return f"SaveBin(header={str(self.header)}, bkheader={str(self.bkheader)}, files=[{', '.join([str(file) for file in self.files])}])"

    @staticmethod
    def from_file(reader: FileIO):
        header = Header.from_file(reader)
        if header is None:
            logging.error("[SaveBin] Could not parse Header")
            return
        bkheader = BkHeader.from_file(reader)
        if bkheader is None:
            logging.error("[SaveBin] Could not parse BkHeader")
            return
        files = SaveFile.unpack_all(reader, bkheader)
        if files is None:
            logging.error("[SaveBin] Could not parse files")
            return
        return SaveBin(header, bkheader, files)

    @staticmethod
    def generate(banner: FileIO, game_version: str):
        files = []
        bkheader = BkHeader.generate(files, game_version)
        header = Header.generate(banner.read(), game_version)
        return SaveBin(header, bkheader, files)

    def to_file(self, writer: FileIO):
        writer.write(self.header.pack())
        data1 = self.bkheader.pack() + SaveFile.pack_all(self.files)
        writer.write(data1)
        data_sha1 = sha1(data1)
        ap_sig, ap_cert = sign(SYSTEM_MENU, data_sha1, self.bkheader.ngid)
        writer.write(ap_sig + struct.pack('>I', SIGNATURE_END_MAGIC) +
                     get_device_certificate(self.bkheader.ngid).pack() + ap_cert)

    def _update_bk_files(self):
        self.bkheader.number_of_files = len(self.files)
        self.bkheader.size_of_files = sum(len(file) for file in self.files)
        self.bkheader.total_size = self.bkheader.size_of_files + FULL_CERT_SZ

    def add_file(self, path, data, mode=0x3f, attributes=0, node_type=1):
        indices = [i for i, f in enumerate(
            self.files) if f.path == path]
        indices.sort(reverse=True)
        # Remove all duplicate occurences
        n_idx = len(indices)
        if n_idx > 0:
            logging.debug(
                f"{n_idx} file{'s' if n_idx > 1 else ''} already exist with the same name. Removing them...")
            for idx in indices:
                self.files.pop(idx)
        logging.debug(f"Adding '{path}'...")
        self.files.append(SaveFile(mode, attributes, node_type, path, data))
        self._update_bk_files()

    def rm_file(self, path):
        indices = [i for i, f in enumerate(
            self.files) if f.path == path]
        indices.sort(reverse=True)
        # Remove all occurences
        n_idx = len(indices)
        if n_idx > 0:
            logging.debug(f"removing '{path}'...")
            for idx in indices:
                self.files.pop(idx)
        self._update_bk_files()

    def config(self):
        return {'tid': self.header.tid, 'permissions': self.header.permissions, 'ngid': self.bkheader.ngid, 'mac_address': struct.unpack('>Q', bytes(2) + self.bkheader.mac_address)[0], 'files': [file.metadata() for file in self.files]}

# +------------------------------+
# | Save file patching functions |
# +------------------------------+


def find_zeldaTp_idx(save_bin: SaveBin):
    idx = -1
    for i in range(len(save_bin.files)):
        file = save_bin.files[i]
        if file.path == "zeldaTp.dat":
            idx = i
    return idx if idx > -1 else None


def update_checksum(data: bytes, fileNumber: int):
    data = bytearray(data)

    offsetFile0 = (fileNumber - 1) * 0xA94 + 0x8
    offsetFile1 = offsetFile0 + 0x2000

    def patchFilesU32(offset: int, value: int):
        data[offsetFile0 + offset:offsetFile0 +
             offset + 4] = struct.pack('>I', value)
        data[offsetFile1 + offset:offsetFile1 +
             offset + 4] = struct.pack('>I', value)

    dataFieldSize = 0xA8C

    dataFieldSum = 0
    for i in range(dataFieldSize):
        dataFieldSum = ctypes.c_uint32(
            dataFieldSum + data[offsetFile0 + i]).value

    # Patch in checksums.
    patchFilesU32(0xA8C, dataFieldSum)
    patchFilesU32(
        0xA90, ctypes.c_uint32(-(dataFieldSum + dataFieldSize)).value)

    return bytes(data)


def patch_file(data: bytes, fileNumber: int, version: str, rel_name: str = "pcrel.bin", bin_data_version='1', file_name=None):
    data = bytearray(data)

    offsetFile0 = (fileNumber - 1) * 0xA94 + 0x8
    offsetFile1 = offsetFile0 + 0x2000

    def patchFilesU16(offset: int, value: int):
        data[offsetFile0 + offset:offsetFile0 +
             offset + 2] = struct.pack('>H', value)
        data[offsetFile1 + offset:offsetFile1 +
             offset + 2] = struct.pack('>H', value)

    def patchFilesU32(offset: int, value: int):
        data[offsetFile0 + offset:offsetFile0 +
             offset + 4] = struct.pack('>I', value)
        data[offsetFile1 + offset:offsetFile1 +
             offset + 4] = struct.pack('>I', value)

    def patchFilesU64(offset: int, value: int):
        data[offsetFile0 + offset:offsetFile0 +
             offset + 8] = struct.pack('>Q', value)
        data[offsetFile1 + offset:offsetFile1 +
             offset + 8] = struct.pack('>Q', value)

    def patchFilesS64(offset: int, value: int):
        data[offsetFile0 + offset:offsetFile0 +
             offset + 8] = struct.pack('>q', value)
        data[offsetFile1 + offset:offsetFile1 +
             offset + 8] = struct.pack('>q', value)

    def patchFilesBytes(offset: int, value: bytes):
        data[offsetFile0 + offset:offsetFile0 + offset + len(value)] = value
        data[offsetFile1 + offset:offsetFile1 + offset + len(value)] = value

    # Set the last save time to the current date (as a kind of build date)
    ticks = (datetime.utcnow() - datetime(2000, 1, 1)
             ).total_seconds() * (OS_BUS_CLOCK / 4)
    patchFilesS64(0x28, int(ticks))

    # Write the new file name (Link's name).
    if file_name is None:
        file_name = b'REL Loader v' + bytes(bin_data_version, 'utf-8')
    else:
        file_name = bytes(file_name, 'utf-8')
    patchFilesBytes(0x1B4, file_name + b'\0')

    # Overwrite the next stage string with a bunch of filler 3s.
    patchFilesBytes(0x58, b"3" * 0x12)

    # Write the pointer to the pointer to the init ASM function.
    patchFilesU32(0x6A, GAME_INFO_PTR[version] + 0x1CC - 0xBC)

    # Write the pointer to the init ASM function.
    patchFilesU32(0x1CC, GAME_INFO_PTR[version] + 0x1E4)

    # Write the init ASM function.
    patchFilesBytes(0x1E4, BIN_DATA_INIT[version])

    # Write the main ASM function.
    patchFilesBytes(
        0x1E4 + len(BIN_DATA_INIT[version]), BIN_DATA_MAIN[bin_data_version][version] + bytes(rel_name, 'utf-8') + b'\x00')

    return update_checksum(data, fileNumber)


def generate_zeldaTp(save_bin: SaveBin):
    data = bytes(0x4000)
    for i in range(1, 4):
        data = update_checksum(data, i)
    save_bin.add_file("zeldaTp.dat", data, 0x34, 0, NodeType.FILE)

# +-------------+
# | Main script |
# +-------------+


def parseFileNumber(string):
    val = int(string)
    if val < 1 or val > 3:
        raise argparse.ArgumentTypeError(
            "File number can only have integer values between 1 and 3")
    return val


def parseFileName(string):
    if len(string) > 12:
        raise argparse.ArgumentTypeError(
            f"File name is too long (12 characters max; got {len(string)})")
    return string


def parseSaveFileName(string):
    if len(string) > 31:
        raise argparse.ArgumentTypeError(
            f"Savefile name is too long (31 characters max; got {len(string)})")
    return string


def directoryPathParser(string):
    if os.path.exists(string):
        if os.path.isfile(string):
            raise argparse.ArgumentTypeError(
                "The output has to be an existing directory or a new directory; Got a file")
    return string


def filePathParser(string):
    if os.path.exists(string):
        if not os.path.isfile(string):
            raise argparse.ArgumentTypeError(
                "The output has to be a file; Got a directory")
    return string


def updateMetaData(save_bin: SaveBin, meta: Dict[str, Any]):
    save_bin.header.tid = meta["tid"] if "tid" in meta else save_bin.header.tid
    save_bin.header.permissions = meta["permissions"] if "permissions" in meta else save_bin.header.permissions
    save_bin.bkheader.ngid = meta["ngid"] if "ngid" in meta else save_bin.bkheader.ngid
    save_bin.bkheader.mac_address = struct.pack(">Q", meta["mac_address"])[
        2:] if "mac_address" in meta else save_bin.bkheader.mac_address
    if "files" in meta:
        for i in range(len(save_bin.files)):
            try:
                idx = [file["path"]
                       for file in meta["files"]].index(save_bin.files[i].path)
                save_bin.files[i].attributes = meta["files"][idx]["attributes"] if "attributes" in meta["files"][idx] else save_bin.files[i].attributes
                save_bin.files[i].mode = meta["files"][idx]["mode"] if "mode" in meta["files"][idx] else save_bin.files[i].mode
                save_bin.files[i].node_type = meta["files"][idx]["type"] if "type" in meta["files"][idx] else save_bin.files[i].node_type
            except ValueError as err:
                continue


def main():
    parser = argparse.ArgumentParser(
        sys.argv[0], description="Tool to pack/unpack Wii saves & inject REL modules.")
    parser.add_argument("-v", "--verbose", action="count",
                        help="increase verbosity of the output", default=1)
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="prevents output to the console", default=False)
    parser.add_argument("-V", "--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(
        dest="command", metavar="command", help="Available commands are: generate, inject, patch, unpack, pack, meta, format, banner, files")
    # Generate
    gen_parser = subparsers.add_parser(
        "generate", description="Generate a new save file", help="Generate a new save file")
    gen_parser.add_argument("-i", "--index", action="append", type=parseFileNumber,
                            help="file number to inject the custom rel into (1 to 3)")
    gen_parser.add_argument("-n", "--name", type=parseFileName,
                            help="overwrite the name of the internal REL file that will be loaded", default="pcrel.bin")
    gen_parser.add_argument("rel", type=argparse.FileType(
        'rb'), help="Path to the REL module to pack")
    gen_parser.add_argument("banner", type=argparse.FileType(
        'rb'), help="Path to the banner of the game")
    gen_parser.add_argument(
        "out", type=str, help="Path where to write the generated save file")
    gen_parser.add_argument("-g", "--game-version", choices=[
                            "us0", "us2", "eu", "jp"], help="Version to generate the save for", required=True)
    gen_parser.add_argument("-m", "--meta", type=argparse.FileType("r"),
                            help="Metadata to use for the save file")
    gen_parser.add_argument("--get-meta", type=argparse.FileType('w'),
                            help="Extract the medatada of the generated save")
    gen_parser.add_argument("-l", "--loader-version", choices=[
                            '1', '2'], help="Choose which version of the loader to put in the save file", default='1')
    gen_parser.add_argument("-f", "--file-name", type=parseSaveFileName,
                            help="The player name in the save file (31 character max)", default=None)
    # Inject
    inj_parser = subparsers.add_parser(
        "inject", description="Injects into an existing save file", help="Injects into an existing save file")
    inj_parser.add_argument("-i", "--index", action="append", type=parseFileNumber,
                            help="file number to inject the custom rel into (1 to 3)")
    inj_parser.add_argument("-n", "--name", type=parseFileName,
                            help="overwrite the name of the internal REL file that will be loaded", default="pcrel.bin")
    inj_parser.add_argument("rel", type=argparse.FileType(
        'rb'), help="Path to the REL module to pack")
    inj_parser.add_argument("save", type=argparse.FileType(
        'rb'), help="Save file to inject into")
    inj_parser.add_argument(
        "out", type=str, help="Path where to write the generated save file")
    inj_parser.add_argument(
        "-g", "--game-version", choices=["us0", "us2", "eu", "jp"], help="Version of the save file")
    inj_parser.add_argument("-m", "--meta", type=argparse.FileType("r"),
                            help="Overwrite the metadata using the provided file")
    inj_parser.add_argument("--get-meta", type=argparse.FileType('w'),
                            help="Extract the medatada of the generated save")
    inj_parser.add_argument(
        "-b", "--banner", type=argparse.FileType("rb"), help="Overwrite the banner")
    inj_parser.add_argument("-l", "--loader-version", choices=[
                            '1', '2'], help="Choose which version of the loader to put in the save file", default='1')
    inj_parser.add_argument("-f", "--file-name", type=parseSaveFileName,
                            help="The player name in the save file (31 character max)", default=None)
    # Patch
    patch_parser = subparsers.add_parser(
        "patch", description="Patches a zeldaTp.dat file", help="Patches a zeldaTp.dat file")
    patch_parser.add_argument("-i", "--index", action="append", type=parseFileNumber,
                              help="file number to inject the custom rel into (1 to 3)")
    patch_parser.add_argument("-n", "--name", type=parseFileName,
                              help="overwrite the name of the internal REL file that will be loaded", default="pcrel.bin")
    patch_parser.add_argument("file", type=argparse.FileType(
        'rb'), help="The zeldaTp.dat file to patch")
    patch_parser.add_argument(
        "out", type=str, help="Where to write the patched file")
    patch_parser.add_argument("-g", "--game-version", choices=[
        "us0", "us2", "eu", "jp"], help="Version to generate the save for", required=True)
    patch_parser.add_argument("-l", "--loader-version", choices=[
        '1', '2'], help="Choose which version of the loader to put in the save file", default='2')
    patch_parser.add_argument("-f", "--file-name", type=parseSaveFileName,
                              help="The player name in the save file (31 character max)", default=None)
    # Unpack
    unpack_parser = subparsers.add_parser(
        "unpack", description="Unpacks a save into a directory", help="Unpacks a save into a directory")
    unpack_parser.add_argument("save", type=argparse.FileType(
        'rb'), help="Path to the save file to unpack")
    unpack_parser.add_argument("out_dir", type=directoryPathParser,
                               help="Path to the directory to unpack the save into")
    unpack_parser.add_argument("--get-meta", type=argparse.FileType('w'),
                               help="Extract the medatada of the generated save")
    # Pack
    pack_parser = subparsers.add_parser(
        "pack", description="Packs a folder into a new save file", help="Packs data files into a new save file")
    pack_parser.add_argument("out_path", type=argparse.FileType(
        'wb'), help="Where to write the packed save")
    pack_parser.add_argument("header", type=argparse.FileType(
        'rb'), help='Path to "header.bin"')
    pack_parser.add_argument("bkheader", type=argparse.FileType(
        'rb'), help='Path to "bkheader.bin"')
    pack_parser.add_argument("files", metavar="file", type=argparse.FileType(
        'rb'), nargs="*", help="Any file you want to pack in the save")
    pack_parser.add_argument(
        "-m", "--meta", type=argparse.FileType("r"), help="Metadata to use for the save file")
    pack_parser.add_argument("--get-meta", type=argparse.FileType('w'),
                             help="Extract the medatada of the generated save")
    # Meta
    meta_parser = subparsers.add_parser(
        "meta", description="Extract metadata from a save file", help="Extract metadata from a save file")
    meta_parser.add_argument("save", type=argparse.FileType(
        'rb'), help="Save file to extract the metadata from")
    meta_parser.add_argument("out", type=argparse.FileType(
        'w'), help="Path the the file where to write the metadata (JSON format)")
    # Format
    format_parser = subparsers.add_parser(
        "format", description="Format a rel file to make it compatible with the loader", help="Format a rel file to make it compatible with the loader")
    format_parser.add_argument("rel", type=argparse.FileType(
        'rb'), help="Path to the REL module to format")
    format_parser.add_argument(
        "out", type=str, help="Where to write the patched file")
    # Banner
    banner_parser = subparsers.add_parser(
        "banner", description="Extract banner from save file", help="Extract banner from save file")
    banner_parser.add_argument("save", type=argparse.FileType(
        'rb'), help="Path to the save file to unpack")
    banner_parser.add_argument("out", type=filePathParser,
                               help="Path to the file to store the banner into")
    # Files
    files_parser = subparsers.add_parser(
        "files", description="Operations on the file inside the save.", help="Operations on the file inside the save.")
    files_subparser = files_parser.add_subparsers(
        dest="files_cmd", metavar="CMD", help="Available commands are: add, list, rm")
    # Files; Add
    files_add_parser = files_subparser.add_parser(
        "add", description="Adds file(s) to a save", help="Adds file(s) to a save")
    files_add_parser.add_argument(
        "save", type=argparse.FileType('rb'), metavar="<save>", help="Path to the save file")
    files_add_parser.add_argument("-o", "--output", nargs='?', type=argparse.FileType(
        'wb'), default=None, help="Path to where to store the result (default: overwrites 'save')")
    files_add_parser.add_argument("file", type=argparse.FileType(
        'rb'), nargs="+", metavar="<file>", help="Path to the file(s) to add to the save")
    # Files; List
    files_list_parser = files_subparser.add_parser(
        "list", description="Lists the file(s) within a given save", help="Lists the files within a given save")
    files_list_parser.add_argument("save", type=argparse.FileType(
        'rb'), metavar="<save>", help="Path to the save file")
    # Files; Remove
    files_rm_parser = files_subparser.add_parser(
        "rm", description="Removes the file(s) within the save", help="Removes the file(s) within the save")
    files_rm_parser.add_argument("save", type=argparse.FileType(
        'rb'), metavar="<save>", help="Path to the save file")
    files_rm_parser.add_argument("-o", "--output", nargs='?', type=argparse.FileType(
        'wb'), default=None, help="Path to where to store the result (default: overwrites 'save')")
    files_rm_parser.add_argument(
        "file", type=str, nargs="+", metavar="<file>", help="Name of the file(s) to remove from the save")
    # Help
    help_parser = subparsers.add_parser(
        "help", description="Get a help guide for a command", help="Get a help guide for a command")
    help_parser.add_argument("cmd", choices=[
                             "generate", "inject", "pack", "unpack", "patch", "meta", "format", "banner", "files", "help"], help="A command you need help with", nargs='?')

    args = parser.parse_args()

    # Phase 1: Extract the simple options and check if it's only looking for a help text.

    if not "command" in args or args.command is None:
        parser.print_help()
        sys.exit(0)

    parsers = {"generate": gen_parser, "inject": inj_parser, "patch": patch_parser,
               "pack": pack_parser, "unpack": unpack_parser, "help": help_parser, "meta": meta_parser, "format": format_parser, "banner": banner_parser, "files": files_parser}

    if args.command == "help":
        if not args.cmd is None:
            parsers[args.cmd].print_help()
        else:
            parser.print_help()
        sys.exit(0)

    verbosity = args.verbose if not args.quiet else 0

    LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    loglevel = LEVELS[min(max(4 - verbosity, 0), 4)]

    numeric_level = getattr(logging, loglevel.upper(), logging.CRITICAL)
    logging.basicConfig(
        level=numeric_level, format="[%(levelname)s]\t[%(asctime)s]\t%(pathname)s:%(lineno)d %(funcName)s: %(message)s")

    # Phase 2: Load files and data/options

    # Phase 2.1: Load and/or generate the Save File (if needed)
    save_bin = None
    if args.command in ["inject", "unpack", "meta", "banner", "files"]:
        # We need to fetch the save_bin from a provided file
        with args.save as save:
            if args.command == "inject":
                prefix_len = len(os.path.commonprefix(
                    [args.rel.name, save.name]))
                logging.info(
                    f"injecting '{'.../' if prefix_len > 0 else ''}{args.rel.name[prefix_len:]}' into '{'.../' if prefix_len > 0 else ''}{args.save.name[prefix_len:]}'")
            save_bin = SaveBin.from_file(save)
        if save_bin is None:
            logging.error("Could not parse save file")
            sys.exit(1)
        logging.info("Loaded SaveBin")
        logging.debug(f"{save_bin}")
    elif args.command == "generate":
        # We need to generate a new save_bin
        logging.info("Generating new save file")
        with args.banner as banner:
            save_bin = SaveBin.generate(banner, args.game_version)
        generate_zeldaTp(save_bin)
        logging.debug(f"{save_bin}")
    elif args.command in ["pack", "patch", "format"]:
        # We don't need any save file
        pass
    else:
        logging.error(f'Error: command not supported {args.command!a}')
        sys.exit(1)

    # Phase 2.2: Make sure we have a valid file index to put the loader into (if needed)

    if args.command in ["inject", "generate", "patch"]:
        # We need to make sure we have the index of the file to patch the loader into. Default is file 3
        if args.index is None:
            logging.info("No file index provided, defaulting to 3")
            args.index = [3]

    # Phase 2.3: Load and process the rel file (if needed)

    rel_bin = None
    if args.command in ["inject", "generate", "format"]:
        # Format the rel file
        with args.rel as rel:
            rel_data = rel.read()
        rel_bin = struct.pack('>I', len(rel_data)) + bytes(0x1C) + rel_data
        size = len(rel_bin)
        logging.info(f"REL file loaded ({size = })")

    # Phase 3: Execute the command and save the results

    if args.command in ["inject", "generate"]:
        # Inject the rel into the save_bin
        args.out = open(args.out, 'wb')
        if args.game_version is None:
            if not save_bin.header.tid in TIDS.keys():
                logging.error(
                    "Error: Game version unrecognized, please provide the --game-version option.")
                sys.exit(1)
            args.game_version = TIDS[save_bin.header.tid]
        logging.info(
            f'Game ID: {save_bin.header.tid >> 32:08x}-{struct.pack(">I", save_bin.header.tid & 0xffffffff).decode()}')
        save_bin.add_file("pcrel.bin", rel_bin)
        zeldaTp_idx = find_zeldaTp_idx(save_bin)
        if not zeldaTp_idx is None:
            for file_idx in args.index:
                save_bin.files[zeldaTp_idx].data = bytes(
                    patch_file(save_bin.files[zeldaTp_idx].data, file_idx, args.game_version, args.name, args.loader_version, args.file_name))
        else:
            logging.error(
                'Error: no "zeldaTp.dat" file in the save archive')
            sys.exit(1)

        if "meta" in args and not args.meta is None:
            meta = json.load(args.meta)
            args.meta.close()
            updateMetaData(save_bin, meta)

        if not args.get_meta is None:
            json.dump(save_bin.config(), args.get_meta,
                      sort_keys=True, indent=4)
            args.get_meta.close()

        logging.debug(f"Produced SaveBin: {save_bin}")

        save_bin.to_file(args.out)
    elif args.command == "unpack":
        path = os.path.realpath(args.out_dir)
        if not os.path.exists(path):
            os.mkdir(path)
        header_file = open(args.out_dir + os.path.sep + "header.bin", 'wb')
        header_file.write(save_bin.header.pack())
        header_file.close()
        bkheader_file = open(args.out_dir + os.path.sep + "bkheader.bin", 'wb')
        bkheader_file.write(save_bin.bkheader.pack())
        bkheader_file.close()
        for file in save_bin.files:
            file_handle = open(args.out_dir + os.path.sep + file.path, 'wb')
            file_handle.write(file.data)
            file_handle.close()

        if not args.get_meta is None:
            json.dump(save_bin.config(), args.get_meta,
                      sort_keys=True, indent=4)
            args.get_meta.close()
    elif args.command == "pack":
        header = Header.unpack(args.header.read())
        bkheader = BkHeader.unpack(args.bkheader.read())
        args.header.close()
        args.bkheader.close()
        save_bin = SaveBin(header, bkheader, [])
        save_bin._update_bk_files()
        for file in args.files:
            save_bin.add_file(os.path.basename(file.name),
                              file.read(), node_type=NodeType.FILE)
            file.close()

        if "meta" in args and not args.meta is None:
            meta = json.load(args.meta)
            args.meta.close()
            updateMetaData(save_bin, meta)

        if not args.get_meta is None:
            json.dump(save_bin.config(), args.get_meta,
                      sort_keys=True, indent=4)
            args.get_meta.close()

        logging.debug(f"Generated SaveBin: {save_bin}")
        save_bin.to_file(args.out_path)
    elif args.command == "patch":
        if args.game_version is None:
            logging.error(
                "Error: Game version required, please provide it through the --game-version option.")
            sys.exit(1)
        zeldaTp_data = args.file.read()
        args.file.close()
        if len(zeldaTp_data) != 0x4000:
            logging.error(
                f"Error: wrong file size (0x{len(zeldaTp_data):08x}; expected 0x4000)")
            sys.exit(1)
        for file_idx in args.index:
            zeldaTp_data = bytes(patch_file(
                zeldaTp_data, file_idx, args.game_version, args.name, args.loader_version, args.file_name))
        out = open(args.out, 'wb')
        out.write(zeldaTp_data)
        out.close()
    elif args.command == "format":
        out = open(args.out, 'wb')
        out.write(rel_bin)
        out.close()
    elif args.command == "banner":
        out = open(args.out, 'wb')
        out.write(save_bin.header.banner)
        out.close()
    elif args.command == "meta":
        json.dump(save_bin.config(), args.out, sort_keys=True, indent=4)
    elif args.command == "files":
        if args.files_cmd == "add":
            file_path = args.save.name
            for file in args.file:
                file_name = os.path.basename(file.name)
                logging.info(f"Loading '{file_name}'...")
                with file as f:
                    file_data = f.read()
                logging.debug(f"Adding '{file_name}'...")
                save_bin.add_file(file_name, file_data)
            if args.output is None:
                logging.info(
                    f"No output file provided, overwritting input save")
                logging.debug(f"({file_path})")
                with open(file_path, 'wb') as f:
                    save_bin.to_file(f)
            else:
                with args.output as out:
                    save_bin.to_file(out)
        elif args.files_cmd == "list":
            print("id\ttype\tmode\tattr\tpath")
            for i, file in enumerate(save_bin.files):
                print(
                    f"#{i:04d}\t{file.node_type.name[:1].upper() + file.node_type.name.lower()[1:]}\t{file.mode}\t{file.attributes}\t{file.path}")
        elif args.files_cmd == "rm":
            file_path = args.save.name
            for file in args.file:
                save_bin.rm_file(file)
            if args.output is None:
                logging.info(
                    f"No output file provided, overwritting input save")
                logging.debug(f"({file_path})")
                with open(file_path, 'wb') as f:
                    save_bin.to_file(f)
            else:
                with args.output as out:
                    save_bin.to_file(out)
        # TODO Add a command to edit a file's properties.
        else:
            raise ValueError(
                f"'{args.files_cmd}' is not a recognized 'files' command.")


if __name__ == "__main__":
    main()