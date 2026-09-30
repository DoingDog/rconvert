import ipaddress
import re
import warnings
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase


@dataclass(frozen=True, slots=True)
class Rule:
    kind: str
    value: str
    options: tuple[str, ...] = ()
    allow: bool = False
    literal_process: bool = False
    native_fields: bool = False

    def __post_init__(self):
        kind = self.kind.upper()
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "options", tuple(sorted({option.lower() for option in self.options})))
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
            object.__setattr__(self, "value", self.value.removesuffix(".").lower())
        elif kind == "DOMAIN-KEYWORD":
            object.__setattr__(self, "value", self.value.lower())


_DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.I)
_PORTS = {"SRC-PORT", "DEST-PORT", "DST-PORT", "IN-PORT"}
_PROCESS = {"PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD",
            "PROCESS-PATH-WILDCARD", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX",
            "IN-NAME", "REMATCH-NAME", "DEVICE-NAME", "USER-AGENT",
            "DOMAIN-REGEX", "URL-REGEX"}
_REGEX = {"DOMAIN-REGEX", "URL-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX"}
_SIMPLE = {"IP-ASN", "SRC-IP-ASN", "GEOIP", "SRC-GEOIP", "GEOSITE",
           "IP-SUFFIX", "SRC-IP-SUFFIX", "SRC-IP", "NETWORK", "PROTOCOL",
           "IN-TYPE", "IN-USER", "UID", "DSCP", "MAC-ADDRESS",
           "HOSTNAME-TYPE", "SUBNET", "CELLULAR-RADIO", "CELLULAR-CARRIER",
           "DOMAIN-KEYWORD"}
_LOGICAL = {"AND", "OR", "NOT"}
_QX_INTERFACE_OPTIONS = {"force-cellular", "multi-interface", "multi-interface-balance", "via-interface=pdp_ip0"}
_QX_INTERFACE_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
                       "IP-CIDR", "IP-CIDR6", "USER-AGENT", "IP-ASN", "GEOIP"}
_BLOCK_ACTIONS = {"REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF",
                  "REJECT-200", "REJECT-IMG", "REJECT-DICT", "REJECT-ARRAY", "ADBLOCK", "ADVERTISINGLITE", "HIJACKING", "PRIVACY", "ZHIHUADS",
                  "ADGUARDSDNSFILTER", "ADVERTISINGMITV", "BLOCKHTTPDNS", "EASYPRIVACY"}
_KINDS = ({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}
          | _PORTS | _PROCESS | _SIMPLE | _LOGICAL)
_SOURCE_KINDS = {"IP-CIDR": "SRC-IP-CIDR", "IP-CIDR6": "SRC-IP-CIDR",
                 "IP-SUFFIX": "SRC-IP-SUFFIX", "GEOIP": "SRC-GEOIP", "IP-ASN": "SRC-IP-ASN"}
# regexp2 v1.11.5 使用 Go unicode.Scripts、Categories、Properties 的键（Go 1.26.5）。
_REGEXP2_UNICODE_PROPERTIES = frozenset("""
ASCII_Hex_Digit Adlam Ahom Anatolian_Hieroglyphs Arabic Armenian Avestan Balinese
Bamum Bassa_Vah Batak Bengali Bhaiksuki Bidi_Control Bopomofo Brahmi
Braille Buginese Buhid C Canadian_Aboriginal Carian Caucasian_Albanian Cc
Cf Chakma Cham Cherokee Chorasmian Cn Co Common
Coptic Cs Cuneiform Cypriot Cypro_Minoan Cyrillic Dash Deprecated
Deseret Devanagari Diacritic Dives_Akuru Dogra Duployan Egyptian_Hieroglyphs Elbasan
Elymaic Ethiopic Extender Georgian Glagolitic Gothic Grantha Greek
Gujarati Gunjala_Gondi Gurmukhi Han Hangul Hanifi_Rohingya Hanunoo Hatran
Hebrew Hex_Digit Hiragana Hyphen IDS_Binary_Operator IDS_Trinary_Operator Ideographic Imperial_Aramaic
Inherited Inscriptional_Pahlavi Inscriptional_Parthian Javanese Join_Control Kaithi Kannada Katakana
Kawi Kayah_Li Kharoshthi Khitan_Small_Script Khmer Khojki Khudawadi L
LC Lao Latin Lepcha Limbu Linear_A Linear_B Lisu
Ll Lm Lo Logical_Order_Exception Lt Lu Lycian Lydian
M Mahajani Makasar Malayalam Mandaic Manichaean Marchen Masaram_Gondi
Mc Me Medefaidrin Meetei_Mayek Mende_Kikakui Meroitic_Cursive Meroitic_Hieroglyphs Miao
Mn Modi Mongolian Mro Multani Myanmar N Nabataean
Nag_Mundari Nandinagari Nd New_Tai_Lue Newa Nko Nl No
Noncharacter_Code_Point Nushu Nyiakeng_Puachue_Hmong Ogham Ol_Chiki Old_Hungarian Old_Italic Old_North_Arabian
Old_Permic Old_Persian Old_Sogdian Old_South_Arabian Old_Turkic Old_Uyghur Oriya Osage
Osmanya Other_Alphabetic Other_Default_Ignorable_Code_Point Other_Grapheme_Extend Other_ID_Continue Other_ID_Start Other_Lowercase Other_Math
Other_Uppercase P Pahawh_Hmong Palmyrene Pattern_Syntax Pattern_White_Space Pau_Cin_Hau Pc
Pd Pe Pf Phags_Pa Phoenician Pi Po Prepended_Concatenation_Mark
Ps Psalter_Pahlavi Quotation_Mark Radical Regional_Indicator Rejang Runic S
STerm Samaritan Saurashtra Sc Sentence_Terminal Sharada Shavian Siddham
SignWriting Sinhala Sk Sm So Soft_Dotted Sogdian Sora_Sompeng
Soyombo Sundanese Syloti_Nagri Syriac Tagalog Tagbanwa Tai_Le Tai_Tham
Tai_Viet Takri Tamil Tangsa Tangut Telugu Terminal_Punctuation Thaana
Thai Tibetan Tifinagh Tirhuta Toto Ugaritic Unified_Ideograph Vai
Variation_Selector Vithkuqi Wancho Warang_Citi White_Space Yezidi Yi Z
Zanabazar_Square Zl Zp Zs
""".split())


# regexp2 v1.12.0 IsWordChar，固定 Go go1.26.8 Unicode 15.0.0 的 L/Mn/Nd/Pc 与 U+200C/U+200D。
# 连续区间使用左闭右开边界；来源：golang/go 的 go1.26.8/src/unicode/tables.go。
_REGEXP2_WORD_BOUNDARIES = (
    0x30, 0x3A, 0x41, 0x5B, 0x5F, 0x60, 0x61, 0x7B, 0xAA, 0xAB, 0xB5, 0xB6,
    0xBA, 0xBB, 0xC0, 0xD7, 0xD8, 0xF7, 0xF8, 0x2C2, 0x2C6, 0x2D2, 0x2E0, 0x2E5,
    0x2EC, 0x2ED, 0x2EE, 0x2EF, 0x300, 0x375, 0x376, 0x378, 0x37A, 0x37E, 0x37F, 0x380,
    0x386, 0x387, 0x388, 0x38B, 0x38C, 0x38D, 0x38E, 0x3A2, 0x3A3, 0x3F6, 0x3F7, 0x482,
    0x483, 0x488, 0x48A, 0x530, 0x531, 0x557, 0x559, 0x55A, 0x560, 0x589, 0x591, 0x5BE,
    0x5BF, 0x5C0, 0x5C1, 0x5C3, 0x5C4, 0x5C6, 0x5C7, 0x5C8, 0x5D0, 0x5EB, 0x5EF, 0x5F3,
    0x610, 0x61B, 0x620, 0x66A, 0x66E, 0x6D4, 0x6D5, 0x6DD, 0x6DF, 0x6E9, 0x6EA, 0x6FD,
    0x6FF, 0x700, 0x710, 0x74B, 0x74D, 0x7B2, 0x7C0, 0x7F6, 0x7FA, 0x7FB, 0x7FD, 0x7FE,
    0x800, 0x82E, 0x840, 0x85C, 0x860, 0x86B, 0x870, 0x888, 0x889, 0x88F, 0x898, 0x8E2,
    0x8E3, 0x903, 0x904, 0x93B, 0x93C, 0x93E, 0x941, 0x949, 0x94D, 0x94E, 0x950, 0x964,
    0x966, 0x970, 0x971, 0x982, 0x985, 0x98D, 0x98F, 0x991, 0x993, 0x9A9, 0x9AA, 0x9B1,
    0x9B2, 0x9B3, 0x9B6, 0x9BA, 0x9BC, 0x9BE, 0x9C1, 0x9C5, 0x9CD, 0x9CF, 0x9DC, 0x9DE,
    0x9DF, 0x9E4, 0x9E6, 0x9F2, 0x9FC, 0x9FD, 0x9FE, 0x9FF, 0xA01, 0xA03, 0xA05, 0xA0B,
    0xA0F, 0xA11, 0xA13, 0xA29, 0xA2A, 0xA31, 0xA32, 0xA34, 0xA35, 0xA37, 0xA38, 0xA3A,
    0xA3C, 0xA3D, 0xA41, 0xA43, 0xA47, 0xA49, 0xA4B, 0xA4E, 0xA51, 0xA52, 0xA59, 0xA5D,
    0xA5E, 0xA5F, 0xA66, 0xA76, 0xA81, 0xA83, 0xA85, 0xA8E, 0xA8F, 0xA92, 0xA93, 0xAA9,
    0xAAA, 0xAB1, 0xAB2, 0xAB4, 0xAB5, 0xABA, 0xABC, 0xABE, 0xAC1, 0xAC6, 0xAC7, 0xAC9,
    0xACD, 0xACE, 0xAD0, 0xAD1, 0xAE0, 0xAE4, 0xAE6, 0xAF0, 0xAF9, 0xB00, 0xB01, 0xB02,
    0xB05, 0xB0D, 0xB0F, 0xB11, 0xB13, 0xB29, 0xB2A, 0xB31, 0xB32, 0xB34, 0xB35, 0xB3A,
    0xB3C, 0xB3E, 0xB3F, 0xB40, 0xB41, 0xB45, 0xB4D, 0xB4E, 0xB55, 0xB57, 0xB5C, 0xB5E,
    0xB5F, 0xB64, 0xB66, 0xB70, 0xB71, 0xB72, 0xB82, 0xB84, 0xB85, 0xB8B, 0xB8E, 0xB91,
    0xB92, 0xB96, 0xB99, 0xB9B, 0xB9C, 0xB9D, 0xB9E, 0xBA0, 0xBA3, 0xBA5, 0xBA8, 0xBAB,
    0xBAE, 0xBBA, 0xBC0, 0xBC1, 0xBCD, 0xBCE, 0xBD0, 0xBD1, 0xBE6, 0xBF0, 0xC00, 0xC01,
    0xC04, 0xC0D, 0xC0E, 0xC11, 0xC12, 0xC29, 0xC2A, 0xC3A, 0xC3C, 0xC41, 0xC46, 0xC49,
    0xC4A, 0xC4E, 0xC55, 0xC57, 0xC58, 0xC5B, 0xC5D, 0xC5E, 0xC60, 0xC64, 0xC66, 0xC70,
    0xC80, 0xC82, 0xC85, 0xC8D, 0xC8E, 0xC91, 0xC92, 0xCA9, 0xCAA, 0xCB4, 0xCB5, 0xCBA,
    0xCBC, 0xCBE, 0xCBF, 0xCC0, 0xCC6, 0xCC7, 0xCCC, 0xCCE, 0xCDD, 0xCDF, 0xCE0, 0xCE4,
    0xCE6, 0xCF0, 0xCF1, 0xCF3, 0xD00, 0xD02, 0xD04, 0xD0D, 0xD0E, 0xD11, 0xD12, 0xD3E,
    0xD41, 0xD45, 0xD4D, 0xD4F, 0xD54, 0xD57, 0xD5F, 0xD64, 0xD66, 0xD70, 0xD7A, 0xD80,
    0xD81, 0xD82, 0xD85, 0xD97, 0xD9A, 0xDB2, 0xDB3, 0xDBC, 0xDBD, 0xDBE, 0xDC0, 0xDC7,
    0xDCA, 0xDCB, 0xDD2, 0xDD5, 0xDD6, 0xDD7, 0xDE6, 0xDF0, 0xE01, 0xE3B, 0xE40, 0xE4F,
    0xE50, 0xE5A, 0xE81, 0xE83, 0xE84, 0xE85, 0xE86, 0xE8B, 0xE8C, 0xEA4, 0xEA5, 0xEA6,
    0xEA7, 0xEBE, 0xEC0, 0xEC5, 0xEC6, 0xEC7, 0xEC8, 0xECF, 0xED0, 0xEDA, 0xEDC, 0xEE0,
    0xF00, 0xF01, 0xF18, 0xF1A, 0xF20, 0xF2A, 0xF35, 0xF36, 0xF37, 0xF38, 0xF39, 0xF3A,
    0xF40, 0xF48, 0xF49, 0xF6D, 0xF71, 0xF7F, 0xF80, 0xF85, 0xF86, 0xF98, 0xF99, 0xFBD,
    0xFC6, 0xFC7, 0x1000, 0x102B, 0x102D, 0x1031, 0x1032, 0x1038, 0x1039, 0x103B, 0x103D, 0x104A,
    0x1050, 0x1056, 0x1058, 0x1062, 0x1065, 0x1067, 0x106E, 0x1083, 0x1085, 0x1087, 0x108D, 0x108F,
    0x1090, 0x109A, 0x109D, 0x109E, 0x10A0, 0x10C6, 0x10C7, 0x10C8, 0x10CD, 0x10CE, 0x10D0, 0x10FB,
    0x10FC, 0x1249, 0x124A, 0x124E, 0x1250, 0x1257, 0x1258, 0x1259, 0x125A, 0x125E, 0x1260, 0x1289,
    0x128A, 0x128E, 0x1290, 0x12B1, 0x12B2, 0x12B6, 0x12B8, 0x12BF, 0x12C0, 0x12C1, 0x12C2, 0x12C6,
    0x12C8, 0x12D7, 0x12D8, 0x1311, 0x1312, 0x1316, 0x1318, 0x135B, 0x135D, 0x1360, 0x1380, 0x1390,
    0x13A0, 0x13F6, 0x13F8, 0x13FE, 0x1401, 0x166D, 0x166F, 0x1680, 0x1681, 0x169B, 0x16A0, 0x16EB,
    0x16F1, 0x16F9, 0x1700, 0x1715, 0x171F, 0x1734, 0x1740, 0x1754, 0x1760, 0x176D, 0x176E, 0x1771,
    0x1772, 0x1774, 0x1780, 0x17B6, 0x17B7, 0x17BE, 0x17C6, 0x17C7, 0x17C9, 0x17D4, 0x17D7, 0x17D8,
    0x17DC, 0x17DE, 0x17E0, 0x17EA, 0x180B, 0x180E, 0x180F, 0x181A, 0x1820, 0x1879, 0x1880, 0x18AB,
    0x18B0, 0x18F6, 0x1900, 0x191F, 0x1920, 0x1923, 0x1927, 0x1929, 0x1932, 0x1933, 0x1939, 0x193C,
    0x1946, 0x196E, 0x1970, 0x1975, 0x1980, 0x19AC, 0x19B0, 0x19CA, 0x19D0, 0x19DA, 0x1A00, 0x1A19,
    0x1A1B, 0x1A1C, 0x1A20, 0x1A55, 0x1A56, 0x1A57, 0x1A58, 0x1A5F, 0x1A60, 0x1A61, 0x1A62, 0x1A63,
    0x1A65, 0x1A6D, 0x1A73, 0x1A7D, 0x1A7F, 0x1A8A, 0x1A90, 0x1A9A, 0x1AA7, 0x1AA8, 0x1AB0, 0x1ABE,
    0x1ABF, 0x1ACF, 0x1B00, 0x1B04, 0x1B05, 0x1B35, 0x1B36, 0x1B3B, 0x1B3C, 0x1B3D, 0x1B42, 0x1B43,
    0x1B45, 0x1B4D, 0x1B50, 0x1B5A, 0x1B6B, 0x1B74, 0x1B80, 0x1B82, 0x1B83, 0x1BA1, 0x1BA2, 0x1BA6,
    0x1BA8, 0x1BAA, 0x1BAB, 0x1BE7, 0x1BE8, 0x1BEA, 0x1BED, 0x1BEE, 0x1BEF, 0x1BF2, 0x1C00, 0x1C24,
    0x1C2C, 0x1C34, 0x1C36, 0x1C38, 0x1C40, 0x1C4A, 0x1C4D, 0x1C7E, 0x1C80, 0x1C89, 0x1C90, 0x1CBB,
    0x1CBD, 0x1CC0, 0x1CD0, 0x1CD3, 0x1CD4, 0x1CE1, 0x1CE2, 0x1CF7, 0x1CF8, 0x1CFB, 0x1D00, 0x1F16,
    0x1F18, 0x1F1E, 0x1F20, 0x1F46, 0x1F48, 0x1F4E, 0x1F50, 0x1F58, 0x1F59, 0x1F5A, 0x1F5B, 0x1F5C,
    0x1F5D, 0x1F5E, 0x1F5F, 0x1F7E, 0x1F80, 0x1FB5, 0x1FB6, 0x1FBD, 0x1FBE, 0x1FBF, 0x1FC2, 0x1FC5,
    0x1FC6, 0x1FCD, 0x1FD0, 0x1FD4, 0x1FD6, 0x1FDC, 0x1FE0, 0x1FED, 0x1FF2, 0x1FF5, 0x1FF6, 0x1FFD,
    0x200C, 0x200E, 0x203F, 0x2041, 0x2054, 0x2055, 0x2071, 0x2072, 0x207F, 0x2080, 0x2090, 0x209D,
    0x20D0, 0x20DD, 0x20E1, 0x20E2, 0x20E5, 0x20F1, 0x2102, 0x2103, 0x2107, 0x2108, 0x210A, 0x2114,
    0x2115, 0x2116, 0x2119, 0x211E, 0x2124, 0x2125, 0x2126, 0x2127, 0x2128, 0x2129, 0x212A, 0x212E,
    0x212F, 0x213A, 0x213C, 0x2140, 0x2145, 0x214A, 0x214E, 0x214F, 0x2183, 0x2185, 0x2C00, 0x2CE5,
    0x2CEB, 0x2CF4, 0x2D00, 0x2D26, 0x2D27, 0x2D28, 0x2D2D, 0x2D2E, 0x2D30, 0x2D68, 0x2D6F, 0x2D70,
    0x2D7F, 0x2D97, 0x2DA0, 0x2DA7, 0x2DA8, 0x2DAF, 0x2DB0, 0x2DB7, 0x2DB8, 0x2DBF, 0x2DC0, 0x2DC7,
    0x2DC8, 0x2DCF, 0x2DD0, 0x2DD7, 0x2DD8, 0x2DDF, 0x2DE0, 0x2E00, 0x2E2F, 0x2E30, 0x3005, 0x3007,
    0x302A, 0x302E, 0x3031, 0x3036, 0x303B, 0x303D, 0x3041, 0x3097, 0x3099, 0x309B, 0x309D, 0x30A0,
    0x30A1, 0x30FB, 0x30FC, 0x3100, 0x3105, 0x3130, 0x3131, 0x318F, 0x31A0, 0x31C0, 0x31F0, 0x3200,
    0x3400, 0x4DC0, 0x4E00, 0xA48D, 0xA4D0, 0xA4FE, 0xA500, 0xA60D, 0xA610, 0xA62C, 0xA640, 0xA670,
    0xA674, 0xA67E, 0xA67F, 0xA6E6, 0xA6F0, 0xA6F2, 0xA717, 0xA720, 0xA722, 0xA789, 0xA78B, 0xA7CB,
    0xA7D0, 0xA7D2, 0xA7D3, 0xA7D4, 0xA7D5, 0xA7DA, 0xA7F2, 0xA823, 0xA825, 0xA827, 0xA82C, 0xA82D,
    0xA840, 0xA874, 0xA882, 0xA8B4, 0xA8C4, 0xA8C6, 0xA8D0, 0xA8DA, 0xA8E0, 0xA8F8, 0xA8FB, 0xA8FC,
    0xA8FD, 0xA92E, 0xA930, 0xA952, 0xA960, 0xA97D, 0xA980, 0xA983, 0xA984, 0xA9B4, 0xA9B6, 0xA9BA,
    0xA9BC, 0xA9BE, 0xA9CF, 0xA9DA, 0xA9E0, 0xA9FF, 0xAA00, 0xAA2F, 0xAA31, 0xAA33, 0xAA35, 0xAA37,
    0xAA40, 0xAA4D, 0xAA50, 0xAA5A, 0xAA60, 0xAA77, 0xAA7A, 0xAA7B, 0xAA7C, 0xAA7D, 0xAA7E, 0xAAC3,
    0xAADB, 0xAADE, 0xAAE0, 0xAAEB, 0xAAEC, 0xAAEE, 0xAAF2, 0xAAF5, 0xAAF6, 0xAAF7, 0xAB01, 0xAB07,
    0xAB09, 0xAB0F, 0xAB11, 0xAB17, 0xAB20, 0xAB27, 0xAB28, 0xAB2F, 0xAB30, 0xAB5B, 0xAB5C, 0xAB6A,
    0xAB70, 0xABE3, 0xABE5, 0xABE6, 0xABE8, 0xABE9, 0xABED, 0xABEE, 0xABF0, 0xABFA, 0xAC00, 0xD7A4,
    0xD7B0, 0xD7C7, 0xD7CB, 0xD7FC, 0xF900, 0xFA6E, 0xFA70, 0xFADA, 0xFB00, 0xFB07, 0xFB13, 0xFB18,
    0xFB1D, 0xFB29, 0xFB2A, 0xFB37, 0xFB38, 0xFB3D, 0xFB3E, 0xFB3F, 0xFB40, 0xFB42, 0xFB43, 0xFB45,
    0xFB46, 0xFBB2, 0xFBD3, 0xFD3E, 0xFD50, 0xFD90, 0xFD92, 0xFDC8, 0xFDF0, 0xFDFC, 0xFE00, 0xFE10,
    0xFE20, 0xFE30, 0xFE33, 0xFE35, 0xFE4D, 0xFE50, 0xFE70, 0xFE75, 0xFE76, 0xFEFD, 0xFF10, 0xFF1A,
    0xFF21, 0xFF3B, 0xFF3F, 0xFF40, 0xFF41, 0xFF5B, 0xFF66, 0xFFBF, 0xFFC2, 0xFFC8, 0xFFCA, 0xFFD0,
    0xFFD2, 0xFFD8, 0xFFDA, 0xFFDD, 0x10000, 0x1000C, 0x1000D, 0x10027, 0x10028, 0x1003B, 0x1003C, 0x1003E,
    0x1003F, 0x1004E, 0x10050, 0x1005E, 0x10080, 0x100FB, 0x101FD, 0x101FE, 0x10280, 0x1029D, 0x102A0, 0x102D1,
    0x102E0, 0x102E1, 0x10300, 0x10320, 0x1032D, 0x10341, 0x10342, 0x1034A, 0x10350, 0x1037B, 0x10380, 0x1039E,
    0x103A0, 0x103C4, 0x103C8, 0x103D0, 0x10400, 0x1049E, 0x104A0, 0x104AA, 0x104B0, 0x104D4, 0x104D8, 0x104FC,
    0x10500, 0x10528, 0x10530, 0x10564, 0x10570, 0x1057B, 0x1057C, 0x1058B, 0x1058C, 0x10593, 0x10594, 0x10596,
    0x10597, 0x105A2, 0x105A3, 0x105B2, 0x105B3, 0x105BA, 0x105BB, 0x105BD, 0x10600, 0x10737, 0x10740, 0x10756,
    0x10760, 0x10768, 0x10780, 0x10786, 0x10787, 0x107B1, 0x107B2, 0x107BB, 0x10800, 0x10806, 0x10808, 0x10809,
    0x1080A, 0x10836, 0x10837, 0x10839, 0x1083C, 0x1083D, 0x1083F, 0x10856, 0x10860, 0x10877, 0x10880, 0x1089F,
    0x108E0, 0x108F3, 0x108F4, 0x108F6, 0x10900, 0x10916, 0x10920, 0x1093A, 0x10980, 0x109B8, 0x109BE, 0x109C0,
    0x10A00, 0x10A04, 0x10A05, 0x10A07, 0x10A0C, 0x10A14, 0x10A15, 0x10A18, 0x10A19, 0x10A36, 0x10A38, 0x10A3B,
    0x10A3F, 0x10A40, 0x10A60, 0x10A7D, 0x10A80, 0x10A9D, 0x10AC0, 0x10AC8, 0x10AC9, 0x10AE7, 0x10B00, 0x10B36,
    0x10B40, 0x10B56, 0x10B60, 0x10B73, 0x10B80, 0x10B92, 0x10C00, 0x10C49, 0x10C80, 0x10CB3, 0x10CC0, 0x10CF3,
    0x10D00, 0x10D28, 0x10D30, 0x10D3A, 0x10E80, 0x10EAA, 0x10EAB, 0x10EAD, 0x10EB0, 0x10EB2, 0x10EFD, 0x10F1D,
    0x10F27, 0x10F28, 0x10F30, 0x10F51, 0x10F70, 0x10F86, 0x10FB0, 0x10FC5, 0x10FE0, 0x10FF7, 0x11001, 0x11002,
    0x11003, 0x11047, 0x11066, 0x11076, 0x1107F, 0x11082, 0x11083, 0x110B0, 0x110B3, 0x110B7, 0x110B9, 0x110BB,
    0x110C2, 0x110C3, 0x110D0, 0x110E9, 0x110F0, 0x110FA, 0x11100, 0x1112C, 0x1112D, 0x11135, 0x11136, 0x11140,
    0x11144, 0x11145, 0x11147, 0x11148, 0x11150, 0x11174, 0x11176, 0x11177, 0x11180, 0x11182, 0x11183, 0x111B3,
    0x111B6, 0x111BF, 0x111C1, 0x111C5, 0x111C9, 0x111CD, 0x111CF, 0x111DB, 0x111DC, 0x111DD, 0x11200, 0x11212,
    0x11213, 0x1122C, 0x1122F, 0x11232, 0x11234, 0x11235, 0x11236, 0x11238, 0x1123E, 0x11242, 0x11280, 0x11287,
    0x11288, 0x11289, 0x1128A, 0x1128E, 0x1128F, 0x1129E, 0x1129F, 0x112A9, 0x112B0, 0x112E0, 0x112E3, 0x112EB,
    0x112F0, 0x112FA, 0x11300, 0x11302, 0x11305, 0x1130D, 0x1130F, 0x11311, 0x11313, 0x11329, 0x1132A, 0x11331,
    0x11332, 0x11334, 0x11335, 0x1133A, 0x1133B, 0x1133E, 0x11340, 0x11341, 0x11350, 0x11351, 0x1135D, 0x11362,
    0x11366, 0x1136D, 0x11370, 0x11375, 0x11400, 0x11435, 0x11438, 0x11440, 0x11442, 0x11445, 0x11446, 0x1144B,
    0x11450, 0x1145A, 0x1145E, 0x11462, 0x11480, 0x114B0, 0x114B3, 0x114B9, 0x114BA, 0x114BB, 0x114BF, 0x114C1,
    0x114C2, 0x114C6, 0x114C7, 0x114C8, 0x114D0, 0x114DA, 0x11580, 0x115AF, 0x115B2, 0x115B6, 0x115BC, 0x115BE,
    0x115BF, 0x115C1, 0x115D8, 0x115DE, 0x11600, 0x11630, 0x11633, 0x1163B, 0x1163D, 0x1163E, 0x1163F, 0x11641,
    0x11644, 0x11645, 0x11650, 0x1165A, 0x11680, 0x116AC, 0x116AD, 0x116AE, 0x116B0, 0x116B6, 0x116B7, 0x116B9,
    0x116C0, 0x116CA, 0x11700, 0x1171B, 0x1171D, 0x11720, 0x11722, 0x11726, 0x11727, 0x1172C, 0x11730, 0x1173A,
    0x11740, 0x11747, 0x11800, 0x1182C, 0x1182F, 0x11838, 0x11839, 0x1183B, 0x118A0, 0x118EA, 0x118FF, 0x11907,
    0x11909, 0x1190A, 0x1190C, 0x11914, 0x11915, 0x11917, 0x11918, 0x11930, 0x1193B, 0x1193D, 0x1193E, 0x11940,
    0x11941, 0x11942, 0x11943, 0x11944, 0x11950, 0x1195A, 0x119A0, 0x119A8, 0x119AA, 0x119D1, 0x119D4, 0x119D8,
    0x119DA, 0x119DC, 0x119E0, 0x119E2, 0x119E3, 0x119E4, 0x11A00, 0x11A39, 0x11A3A, 0x11A3F, 0x11A47, 0x11A48,
    0x11A50, 0x11A57, 0x11A59, 0x11A97, 0x11A98, 0x11A9A, 0x11A9D, 0x11A9E, 0x11AB0, 0x11AF9, 0x11C00, 0x11C09,
    0x11C0A, 0x11C2F, 0x11C30, 0x11C37, 0x11C38, 0x11C3E, 0x11C3F, 0x11C41, 0x11C50, 0x11C5A, 0x11C72, 0x11C90,
    0x11C92, 0x11CA8, 0x11CAA, 0x11CB1, 0x11CB2, 0x11CB4, 0x11CB5, 0x11CB7, 0x11D00, 0x11D07, 0x11D08, 0x11D0A,
    0x11D0B, 0x11D37, 0x11D3A, 0x11D3B, 0x11D3C, 0x11D3E, 0x11D3F, 0x11D48, 0x11D50, 0x11D5A, 0x11D60, 0x11D66,
    0x11D67, 0x11D69, 0x11D6A, 0x11D8A, 0x11D90, 0x11D92, 0x11D95, 0x11D96, 0x11D97, 0x11D99, 0x11DA0, 0x11DAA,
    0x11EE0, 0x11EF5, 0x11F00, 0x11F03, 0x11F04, 0x11F11, 0x11F12, 0x11F34, 0x11F36, 0x11F3B, 0x11F40, 0x11F41,
    0x11F42, 0x11F43, 0x11F50, 0x11F5A, 0x11FB0, 0x11FB1, 0x12000, 0x1239A, 0x12480, 0x12544, 0x12F90, 0x12FF1,
    0x13000, 0x13430, 0x13440, 0x13456, 0x14400, 0x14647, 0x16800, 0x16A39, 0x16A40, 0x16A5F, 0x16A60, 0x16A6A,
    0x16A70, 0x16ABF, 0x16AC0, 0x16ACA, 0x16AD0, 0x16AEE, 0x16AF0, 0x16AF5, 0x16B00, 0x16B37, 0x16B40, 0x16B44,
    0x16B50, 0x16B5A, 0x16B63, 0x16B78, 0x16B7D, 0x16B90, 0x16E40, 0x16E80, 0x16F00, 0x16F4B, 0x16F4F, 0x16F51,
    0x16F8F, 0x16FA0, 0x16FE0, 0x16FE2, 0x16FE3, 0x16FE5, 0x17000, 0x187F8, 0x18800, 0x18CD6, 0x18D00, 0x18D09,
    0x1AFF0, 0x1AFF4, 0x1AFF5, 0x1AFFC, 0x1AFFD, 0x1AFFF, 0x1B000, 0x1B123, 0x1B132, 0x1B133, 0x1B150, 0x1B153,
    0x1B155, 0x1B156, 0x1B164, 0x1B168, 0x1B170, 0x1B2FC, 0x1BC00, 0x1BC6B, 0x1BC70, 0x1BC7D, 0x1BC80, 0x1BC89,
    0x1BC90, 0x1BC9A, 0x1BC9D, 0x1BC9F, 0x1CF00, 0x1CF2E, 0x1CF30, 0x1CF47, 0x1D167, 0x1D16A, 0x1D17B, 0x1D183,
    0x1D185, 0x1D18C, 0x1D1AA, 0x1D1AE, 0x1D242, 0x1D245, 0x1D400, 0x1D455, 0x1D456, 0x1D49D, 0x1D49E, 0x1D4A0,
    0x1D4A2, 0x1D4A3, 0x1D4A5, 0x1D4A7, 0x1D4A9, 0x1D4AD, 0x1D4AE, 0x1D4BA, 0x1D4BB, 0x1D4BC, 0x1D4BD, 0x1D4C4,
    0x1D4C5, 0x1D506, 0x1D507, 0x1D50B, 0x1D50D, 0x1D515, 0x1D516, 0x1D51D, 0x1D51E, 0x1D53A, 0x1D53B, 0x1D53F,
    0x1D540, 0x1D545, 0x1D546, 0x1D547, 0x1D54A, 0x1D551, 0x1D552, 0x1D6A6, 0x1D6A8, 0x1D6C1, 0x1D6C2, 0x1D6DB,
    0x1D6DC, 0x1D6FB, 0x1D6FC, 0x1D715, 0x1D716, 0x1D735, 0x1D736, 0x1D74F, 0x1D750, 0x1D76F, 0x1D770, 0x1D789,
    0x1D78A, 0x1D7A9, 0x1D7AA, 0x1D7C3, 0x1D7C4, 0x1D7CC, 0x1D7CE, 0x1D800, 0x1DA00, 0x1DA37, 0x1DA3B, 0x1DA6D,
    0x1DA75, 0x1DA76, 0x1DA84, 0x1DA85, 0x1DA9B, 0x1DAA0, 0x1DAA1, 0x1DAB0, 0x1DF00, 0x1DF1F, 0x1DF25, 0x1DF2B,
    0x1E000, 0x1E007, 0x1E008, 0x1E019, 0x1E01B, 0x1E022, 0x1E023, 0x1E025, 0x1E026, 0x1E02B, 0x1E030, 0x1E06E,
    0x1E08F, 0x1E090, 0x1E100, 0x1E12D, 0x1E130, 0x1E13E, 0x1E140, 0x1E14A, 0x1E14E, 0x1E14F, 0x1E290, 0x1E2AF,
    0x1E2C0, 0x1E2FA, 0x1E4D0, 0x1E4FA, 0x1E7E0, 0x1E7E7, 0x1E7E8, 0x1E7EC, 0x1E7ED, 0x1E7EF, 0x1E7F0, 0x1E7FF,
    0x1E800, 0x1E8C5, 0x1E8D0, 0x1E8D7, 0x1E900, 0x1E94C, 0x1E950, 0x1E95A, 0x1EE00, 0x1EE04, 0x1EE05, 0x1EE20,
    0x1EE21, 0x1EE23, 0x1EE24, 0x1EE25, 0x1EE27, 0x1EE28, 0x1EE29, 0x1EE33, 0x1EE34, 0x1EE38, 0x1EE39, 0x1EE3A,
    0x1EE3B, 0x1EE3C, 0x1EE42, 0x1EE43, 0x1EE47, 0x1EE48, 0x1EE49, 0x1EE4A, 0x1EE4B, 0x1EE4C, 0x1EE4D, 0x1EE50,
    0x1EE51, 0x1EE53, 0x1EE54, 0x1EE55, 0x1EE57, 0x1EE58, 0x1EE59, 0x1EE5A, 0x1EE5B, 0x1EE5C, 0x1EE5D, 0x1EE5E,
    0x1EE5F, 0x1EE60, 0x1EE61, 0x1EE63, 0x1EE64, 0x1EE65, 0x1EE67, 0x1EE6B, 0x1EE6C, 0x1EE73, 0x1EE74, 0x1EE78,
    0x1EE79, 0x1EE7D, 0x1EE7E, 0x1EE7F, 0x1EE80, 0x1EE8A, 0x1EE8B, 0x1EE9C, 0x1EEA1, 0x1EEA4, 0x1EEA5, 0x1EEAA,
    0x1EEAB, 0x1EEBC, 0x1FBF0, 0x1FBFA, 0x20000, 0x2A6E0, 0x2A700, 0x2B73A, 0x2B740, 0x2B81E, 0x2B820, 0x2CEA2,
    0x2CEB0, 0x2EBE1, 0x2F800, 0x2FA1E, 0x30000, 0x3134B, 0x31350, 0x323B0, 0xE0100, 0xE01F0,
)


def _delimiters(line: str, *, native_fields: bool = False):
    # 仅扫描调用者给出的范围；来源策略和注释由 _source_parts 消费。
    stack = []
    start, escaped, quote = 0, False, None
    regex_depth = literal_depth = None
    class_first = class_hyphen = extended = regex_comment = False
    index = 0
    while index < len(line):
        char = line[index]
        if native_fields:
            if char == '(':
                stack.append(index)
            elif char == ')':
                if not stack:
                    raise ValueError("unbalanced delimiters")
                stack.pop()
            elif char == ',' and not stack:
                yield ',', index
            index += 1
            continue
        in_class = bool(stack and stack[-1][0] == '[')
        if regex_comment:
            if char == ')' and regex_depth and len(stack) == regex_depth:
                stack.pop()
                regex_depth = None
                regex_comment = extended = False
            index += 1
            continue
        if escaped:
            escaped = False
            if in_class:
                class_first = class_hyphen = False
            if regex_depth is not None and char == 'c':
                index += 1
        elif char == '\\':
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"" and not line[start:index].strip() and regex_depth is None:
            quote = char
        elif in_class:
            subtraction = char == '[' and class_hyphen
            class_hyphen = char == '-' and not class_first
            if subtraction:
                stack.append(('[', index))
                class_first = True
            elif char == ']':
                if class_first:
                    class_first = False
                else:
                    stack.pop()
            elif char != '^' or index != stack[-1][1] + 1:
                class_first = False
        elif regex_depth is not None and line.startswith('(?#', index):
            end = line.find(')', index + 3)
            if end < 0:
                raise ValueError("unbalanced delimiters")
            index = end + 1
            continue
        elif regex_depth is not None and extended and char == '#':
            if not stack and index and line[index - 1].isspace():
                yield 'comment', index
            regex_comment = True
        elif regex_depth is not None and char == '{':
            quantifier = re.match(r"\{[0-9]+(?:,[0-9]*)?\}", line[index:])
            if quantifier:
                index += len(quantifier[0])
                continue
        elif regex_depth is not None and char == '[':
            stack.append(('[', index))
            class_first = True
        elif char == '(' and (literal_depth is None or literal_depth > 0):
            if regex_depth is not None:
                flags = re.match(r"\(\?([imsx]*)(?:-([imsx]+))?([):])", line[index:])
                if flags and (flags[1] or flags[2]):
                    if flags[3] == ':':
                        stack.append(('(', index, extended))
                    extended = (extended or 'x' in flags[1]) and not (flags[2] and 'x' in flags[2])
                    index += len(flags[0])
                    continue
                stack.append(('(', index, extended))
            else:
                stack.append(('(', index))
        elif char == ')':
            if stack and stack[-1][0] == '(':
                opened = stack.pop()
                if len(opened) == 3:
                    extended = opened[2]
                if regex_depth is not None and len(stack) < regex_depth:
                    regex_depth = None
                    extended = False
                if literal_depth is not None and len(stack) < literal_depth:
                    literal_depth = None
            elif regex_depth is None and literal_depth is None:
                raise ValueError("unbalanced delimiters")
        elif char == ',':
            if regex_depth is None and literal_depth is None:
                scope_start = stack[-1][1] + 1 if stack else start
                kind = line[scope_start:index].strip().upper()
                if kind in _REGEX:
                    # 明确字段引用始终由字段起始引号保护。
                    following = line[index + 1:].lstrip()
                    if not following.startswith(("'", '"')):
                        regex_depth = len(stack)
                elif kind in _KINDS and kind not in _LOGICAL:
                    literal_depth = len(stack)
            if not stack:
                yield ',', index
            start = index + 1
        elif (not stack and index and line[index - 1].isspace()
              and (char in '#;' or line.startswith('//', index))):
            yield 'comment', index
        index += 1
    if stack or quote:
        raise ValueError("unbalanced delimiters")


def _field_value(value: str) -> str:
    if len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]:
        if value[0] == '"':
            # Surge 双引号字段只解码字面引号和反斜杠；regex 的其他 escape 保留。
            return re.sub(r'\\(["\\])', r'\1', value[1:-1])
        return value[1:-1]
    return value


def _native_parts(line: str) -> list[str]:
    parts = [part.strip(' ') for part in line.split(',')]
    parts[0] = parts[0].upper()
    if parts[0] in (_REGEX - {'URL-REGEX'}) | _LOGICAL and len(parts) > 1:
        return [parts[0], ','.join(parts[1:])]
    return parts


def _fields(line: str, *, scope: str = 'condition', native_fields: bool = False) -> list[str]:
    if scope == 'condition':
        if native_fields:
            return _native_parts(line)
        kind, separator, value = line.partition(',')
        if separator and kind.strip().upper() in _REGEX:
            return [kind.strip(), value.strip()]
    elif scope != 'children':
        raise ValueError(f"invalid field scope: {scope}")
    positions = [-1, *(index for token, index in _delimiters(line, native_fields=native_fields)
                      if token == ','), len(line)]
    trim = ' ' if native_fields else None
    return [line[begin + 1:end].strip(trim) for begin, end in zip(positions, positions[1:])]


def _literal_fields(line: str) -> tuple[list[str], int]:
    parts, start, quote, escaped = [], 0, None, False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"" and not line[start:index].strip():
            quote = char
        elif index and line[index - 1].isspace() and (char in '#;' or line.startswith('//', index)):
            return parts + [line[start:index].strip()], index
        elif char == ',':
            parts.append(line[start:index].strip())
            start = index + 1
    if quote:
        raise ValueError("unbalanced delimiters")
    return parts + [line[start:].strip()], len(line)


def _source_parts(line: str) -> tuple[list[str], int]:
    head, separator, value = line.partition(',')
    kind = head.strip().upper()
    if not separator:
        _, end = _literal_fields(line)
        return [line[:end].strip()], end
    value_start = len(head) + 1
    offset = value_start + len(value) - len(value.lstrip())
    if kind in _REGEX and line[offset:offset + 1] not in ("'", '"'):
        commas = False
        try:
            for token, index in _delimiters(line):
                if index == len(head):
                    continue
                if token == 'comment':
                    message = 'ambiguous unquoted regex comma or policy' if commas else 'ambiguous unquoted regex comment'
                    raise ValueError(message)
                commas = True
                action = re.match(r"\s*([a-z0-9-]+)(?=,|\s+(?:[#;]|//)|$)", line[index + 1:], re.I)
                if action and action[1].upper() in _BLOCK_ACTIONS | {'DIRECT', 'PROXY', 'LIST'}:
                    tail, end = _literal_fields(line[index + 1:])
                    return [head.strip(), line[value_start:index].strip(), *tail], index + 1 + end
        except ValueError:
            if commas:
                raise ValueError('ambiguous unquoted regex comma or policy') from None
            raise
        if commas:
            raise ValueError('ambiguous unquoted regex comma or policy')
        return [head.strip(), value.strip()], len(line)
    if kind in _REGEX:
        quote = line[offset]
        index, escaped = offset + 1, False
        while index < len(line):
            char = line[index]
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                break
            index += 1
        else:
            raise ValueError('unbalanced delimiters')
        rest = line[index + 1:]
        parts, end = _literal_fields(rest)
        if parts[0]:
            raise ValueError('unexpected fields')
        return [head.strip(), line[offset:index + 1], *parts[1:]], index + 1 + end
    # 逻辑字段的包装括号给出完整范围，之后的策略仅按字面字段读取。
    if kind in _LOGICAL:
        for token, index in _delimiters(line):
            if token == ',' and index > len(head):
                tail, end = _literal_fields(line[index + 1:])
                return [head.strip(), line[value_start:index].strip(), *tail], index + 1 + end
            if token == 'comment':
                return [head.strip(), line[value_start:index].strip()], index
        return [head.strip(), value.strip()], len(line)
    # 普通进程字段中的 marker 是字面内容；确定尾字段或注释后停止范围扫描。
    process = kind in {'PROCESS-NAME', 'PROCESS-PATH', 'PROCESS-NAME-WILDCARD', 'PROCESS-PATH-WILDCARD'}
    for token, index in _delimiters(line):
        if token == 'comment' and not process:
            fields, _ = _literal_fields(line[:index])
            return fields, index
        if token == ',' and index > len(head):
            tail, end = _literal_fields(line[index + 1:])
            return [head.strip(), line[value_start:index].strip(), *tail], index + 1 + end
    return [head.strip(), value.strip()], len(line)


def _valid_domain(kind: str, value: str) -> bool:
    value = value.removesuffix('.')
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    if kind == "DOMAIN-WILDCARD":
        value = re.sub(r"\[[a-z0-9-]+\]", "x", value, flags=re.I)
        if '[' in value or ']' in value:
            return False
        value = value.replace('*', 'x').replace('?', 'x')
    if kind == "DOMAIN-SUFFIX" and '.' not in value:
        return bool(_DOMAIN.fullmatch('x.' + value))
    return bool(_DOMAIN.fullmatch(value))


def _valid_deep_regex(probe: str) -> bool:
    # 逐层验证普通组，再以空组原子替换已验证内容，保留父组的量词与分支语法。
    groups, escaped, in_class, class_first = [[]], False, False, False
    class_start = 0
    for index, char in enumerate(probe):
        if escaped:
            groups[-1].extend(('\\', char))
            escaped = False
            if in_class:
                class_first = False
            continue
        if char == '\\':
            escaped = True
            continue
        if char == '[' and not in_class:
            in_class = class_first = True
            class_start = index
        elif char == ']' and in_class:
            if class_first:
                class_first = False
            else:
                in_class = False
        elif in_class:
            if char != '^' or index != class_start + 1:
                class_first = False
        elif char == '(':
            if probe[index + 1:index + 2] == '?':
                return False
            groups.append([])
            continue
        elif char == ')':
            if len(groups) == 1:
                return False
            try:
                re.compile(''.join(groups.pop()))
            except (re.error, OverflowError, RecursionError):
                return False
            groups[-1].append('(?:)')
            continue
        groups[-1].append(char)
    if len(groups) != 1 or escaped or in_class:
        return False
    try:
        re.compile(''.join(groups[0]))
    except (re.error, OverflowError, RecursionError):
        return False
    return True


def _regexp2_word_char(char: str) -> bool:
    return bisect_right(_REGEXP2_WORD_BOUNDARIES, ord(char)) % 2 == 1


def _scan_capture_name(value: str, start: int) -> tuple[str, int, bool]:
    end = start
    numeric = start < len(value) and '0' <= value[start] <= '9'
    while end < len(value) and ('0' <= value[end] <= '9' if numeric else _regexp2_word_char(value[end])):
        end += 1
    return value[start:end], end, numeric


def _capture_number(digits: str) -> int | None:
    digits = digits.lstrip('0') or '0'
    limit = '2147483647'
    if len(digits) > len(limit) or len(digits) == len(limit) and digits > limit:
        return None
    return int(digits)


def _valid_regex(kind: str, value: str) -> bool:
    if not value:
        return False
    probe, in_class, index, names, quantified = [], False, 0, {}, False
    class_atom, range_from_literal, extended = None, False, False
    class_first = class_hyphen = False
    class_start, class_probe, classes = 0, 0, []
    extended_stack, conditionals, references = [], [], []
    captures, explicit_capture, capture_slots = 0, False, {0}
    conditional_head = False
    while index < len(value) and kind != "URL-REGEX":
        char = value[index]
        if not in_class and value.startswith("(?#", index):
            end = value.find(")", index + 3)
            if end < 0:
                return False
            probe.append("(?#)")
            index = end + 1
            quantified = False
            continue
        if char == "\\":
            if index + 1 == len(value):
                return False
            quantified = False
            escape = value[index + 1]
            if in_class:
                class_first = class_hyphen = False
            if escape in "NQE" or in_class and escape == 'k':
                return False
            if escape in "ec":
                if escape == 'c':
                    letter = value[index + 2:index + 3]
                    if 'a' <= letter <= 'z':
                        letter = chr(ord(letter) - 32)
                    if not '@' <= letter <= '_':
                        return False
                    index += 3
                    probe.append(r'\x' + f'{ord(letter) ^ 64:02x}')
                else:
                    index += 2
                    probe.append(r'\x1b')
                if in_class:
                    class_atom, range_from_literal = 'literal', False
                continue
            if escape in "pP":
                if value.startswith("{", index + 2):
                    end = value.find("}", index + 3)
                    if end < 0:
                        return False
                    key = value[index + 3:end]
                else:
                    end = index + 2
                    key = value[end:end + 1]
                if key not in _REGEXP2_UNICODE_PROPERTIES or in_class and range_from_literal:
                    return False
                probe.append("a")
                if in_class:
                    class_atom, range_from_literal = "class", False
                index = end + 1
                continue
            if in_class and escape in "dDsSwW":
                if range_from_literal:
                    return False
                probe.append("a")
                class_atom, range_from_literal = "class", False
                index += 2
                continue
            if escape == "x" and value.startswith("{", index + 2):
                end = value.find("}", index + 3)
                if end < 0:
                    return False
                digits = value[index + 3:end]
                if not re.fullmatch(r"[0-9a-fA-F]{1,6}", digits) or int(digits, 16) > 0x10ffff:
                    return False
                probe.append(re.escape(chr(int(digits, 16))))
                if in_class:
                    class_atom, range_from_literal = "literal", False
                index = end + 1
                continue
            if not in_class and escape in "Gz":
                probe.append(r"\A" if escape == "G" else r"\Z")
            elif not in_class and value.startswith((r"\k<", r"\k'", r"\<", r"\'"), index):
                offset = 3 if escape == 'k' else 2
                closing = ">" if value[index + offset - 1] == "<" else "'"
                key, end, numeric = _scan_capture_name(value, index + offset)
                if numeric and _capture_number(key) is None:
                    return False
                if not key or value[end:end + 1] != closing:
                    if escape == 'k':
                        return False
                    probe.append(value[index:index + 2])
                    index += 2
                    continue
                references.append((key, numeric, 'group', len(probe)))
                probe.append('a')
                index = end + 1
                continue
            elif not in_class and escape in '123456789':
                digits = re.match(r'[0-9]+', value[index + 1:])[0]
                if _capture_number(digits) is None:
                    return False
                references.append((digits, True, 'bare', len(probe)))
                probe.append('a')
                index += len(digits) + 1
                continue
            elif escape in '01234567':
                digits = re.match(r'[0-7]{1,3}', value[index + 1:])[0]
                probe.append(re.escape(chr(int(digits, 8) & 255)))
                if in_class:
                    class_atom, range_from_literal = 'literal', False
                index += len(digits) + 1
                continue
            elif _regexp2_word_char(escape) and escape not in 'abfnrtvuxdDsSwWBAZ':
                return False
            else:
                if in_class and escape == "-" and range_from_literal:
                    index += 2
                    continue
                probe.append(value[index:index + 2])
            if in_class:
                class_atom, range_from_literal = ("escaped_hyphen" if escape == "-" else "literal"), False
            index += 2
            continue
        if extended and not in_class and char.isspace():
            index += 1
            continue
        if extended and not in_class and char == "#":
            break
        if not in_class and char == "{":
            count = re.match(r"\{[0-9]+(?:,[0-9]*)?\}", value[index:])
            if count is not None:
                probe.append(count[0])
                index += len(count[0])
                quantified = True
                continue
        if not in_class and char == "+" and quantified:
            return False
        quantified = not in_class and char in "*+?"
        if not in_class and char == "(":
            if value.startswith(('(?(?=', '(?(?!', '(?(?<=', '(?(?<!'), index):
                extended_stack.append((extended, explicit_capture))
                conditionals.append([len(extended_stack), 0])
                probe.append('(?:')
                index += 2
                continue
            if value.startswith('(?(', index):
                key, end, numeric = _scan_capture_name(value, index + 3)
                if numeric and (value[end:end + 1] != ')' or _capture_number(key) is None):
                    return False
                extended_stack.append((extended, explicit_capture))
                conditionals.append([len(extended_stack), 0])
                probe.append('(?:')
                if key and value[end:end + 1] == ')':
                    # 条件头不分配捕获槽，引用在完整捕获集合建立后验证。
                    references.append((key, numeric, 'condition', None))
                    index = end + 1
                else:
                    head = value[index + 2:]
                    if head.startswith(('(?#', "(?'")) or (head.startswith('(?<') and head[3:4] not in {'=', '!'}):
                        return False
                    conditional_head = True
                    index += 2
                continue
            if conditional_head:
                conditional_head = False
                extended_stack.append((extended, explicit_capture))
                probe.append('(?:')
                index += 1
                continue
            flags = re.match(r"\(\?([imsx]*)(?:-([imsx]+))?\)", value[index:])
            if flags is not None and (flags[1] or flags[2]):
                extended = (extended or "x" in flags[1]) and not (flags[2] and "x" in flags[2])
                following = value[index + len(flags[0]):]
                if extended:
                    following = following.lstrip()
                if following.startswith(("*", "+", "?")) or re.match(r"\{[0-9]+(?:,[0-9]*)?\}", following):
                    return False
                probe.append(f"(?{flags[1]}{'-' + flags[2] if flags[2] else ''}:)")
                index += len(flags[0])
                continue
            scoped = re.match(r"\(\?([imsx]*)(?:-([imsx]+))?:", value[index:])
            if scoped is not None and (scoped[1] or scoped[2]):
                extended_stack.append((extended, explicit_capture))
                extended = (extended or "x" in scoped[1]) and not (scoped[2] and "x" in scoped[2])
                probe.append(scoped[0])
                index += len(scoped[0])
                continue
            extended_stack.append((extended, explicit_capture))
            if value[index + 1:index + 2] != '?':
                if explicit_capture:
                    probe.append('(?:')
                    index += 1
                    continue
                captures += 1
        if char == "[" and not in_class:
            in_class = class_first = True
            class_start, class_probe = index, len(probe)
            class_atom, range_from_literal = None, False
        elif char == "[" and in_class and class_hyphen:
            class_hyphen = False
            classes.append((class_start, class_probe))
            probe.pop()
            class_start, class_probe = index, len(probe)
            class_first = True
            class_atom, range_from_literal = None, False
        elif char == "]" and in_class:
            class_hyphen = False
            if class_first:
                class_first = False
                class_atom, range_from_literal = "literal", False
            elif classes:
                try:
                    re.compile(''.join(probe[class_probe:]) + ']')
                except (re.error, OverflowError):
                    return False
                del probe[class_probe:]
                class_start, class_probe = classes.pop()
                class_atom, range_from_literal = "literal", False
                if value[index + 1:index + 2] != ']':
                    return False
                index += 1
                continue
            else:
                in_class = False
                class_atom, range_from_literal = None, False
        elif char == ")" and not in_class and extended_stack:
            extended, explicit_capture = extended_stack.pop()
            if conditionals and len(extended_stack) < conditionals[-1][0]:
                conditionals.pop()
        elif in_class:
            class_hyphen = char == '-' and not class_first
            if char != '^' or index != class_start + 1:
                class_first = False
            if char == "-":
                if class_atom in {"class", "escaped_hyphen"}:
                    probe.append(r"\-")
                    class_atom, range_from_literal = "literal", False
                    index += 1
                    continue
                if class_atom is None or value[index + 1:index + 2] == "]":
                    class_atom, range_from_literal = "literal", False
                else:
                    range_from_literal = class_atom == "literal"
                    class_atom = None
            elif char != "^" or index != class_start + 1:
                class_atom, range_from_literal = "literal", False
        elif char == "(" and not in_class and value.startswith("(?P", index):
            return False
        elif char == "(" and not in_class and re.match(r"\(\?[aLu](?:\)|:)", value[index:]):
            return False
        elif char == "(" and not in_class and value.startswith("(?n:", index):
            explicit_capture = True
            probe.append("(?:")
            index += 4
            continue
        elif char == "(" and not in_class and value.startswith(("(?<", "(?'"), index):
            marker = value[index + 2]
            if marker == "<" and value[index + 3:index + 4] in {"=", "!"}:
                probe.append("(?:")
                index += 4
                continue
            key, end, numeric = _scan_capture_name(value, index + 3)
            balance = ''
            if value[end:end + 1] == '-':
                balance, end, balance_numeric = _scan_capture_name(value, end + 1)
                if not balance:
                    return False
                references.append((balance, balance_numeric, 'group', None))
            if not (key or balance) or value[end:end + 1] != ('>' if marker == '<' else "'"):
                return False
            index = end + 1
            if not key:
                probe.append('(?:')
                continue
            if numeric:
                number = _capture_number(key)
                if number is None or number == 0:
                    return False
                if key.startswith('0'):
                    references.append((key, True, 'group', None))
                else:
                    capture_slots.add(number)
                probe.append('(')
                continue
            alias = f'g{len(probe)}'
            names[key] = alias
            probe.append(f"(?P<{alias}>")
            continue
        elif char == '|' and not in_class and conditionals and len(extended_stack) == conditionals[-1][0]:
            conditionals[-1][1] += 1
            if conditionals[-1][1] > 1:
                return False
        probe.append(char)
        index += 1
    if in_class or classes:
        return False
    capture_slots.update(range(1, captures + 1))
    slot = captures + 1
    for _ in names:
        while slot in capture_slots:
            slot += 1
        capture_slots.add(slot)
        slot += 1
    for key, numeric, form, position in references:
        if numeric:
            number = _capture_number(key)
            if number is None:
                return False
            if number in capture_slots:
                continue
            if form != 'bare' or number <= 9 or key[0] not in '1234567':
                return False
            # regexp2 先扫描完整 decimal，再对未定义的多位引用按至多三个 octal 数字处理。
            octal = re.match(r'[0-7]{1,3}', key)[0]
            probe[position] = re.escape(chr(int(octal, 8) & 255)) + key[len(octal):]
        elif key not in names:
            # regexp2 将未定义的词语条件作为无捕获的表达式条件。
            if form != 'condition':
                return False
    try:
        re.compile(value if kind == "URL-REGEX" else "".join(probe))
    except RecursionError:
        return kind != "URL-REGEX" and _valid_deep_regex(''.join(probe))
    except (re.error, OverflowError):
        return False
    return True


def _port_comparison(value: str) -> str | None:
    match = re.fullmatch(r"([<>]=?)([0-9]+)", value)
    if not match or len(match[2].lstrip('0')) > 5:
        return None
    number = int(match[2].lstrip('0') or '0')
    lower = number + (match[1] == '>') if match[1].startswith('>') else 1
    upper = number - (match[1] == '<') if match[1].startswith('<') else 65535
    if not 1 <= lower <= upper <= 65535:
        return None
    return str(lower) if lower == upper else f"{lower}-{upper}"


def _valid_port(value: str) -> bool:
    if '/' in value:
        return all(not part.startswith(('<', '>')) and _valid_port(part)
                   for part in value.split('/'))
    if value.startswith(('<', '>')):
        return _port_comparison(value) is not None
    ports = value.split('-')
    numbers = [port.lstrip('0') for port in ports]
    return (1 <= len(ports) <= 2 and
            all(port.isascii() and port.isdecimal() and 0 < len(number) <= 5
                and int(number) <= 65535 for port, number in zip(ports, numbers)) and
            (len(ports) == 1 or int(numbers[0]) <= int(numbers[1])))


def _valid_simple(kind: str, value: str) -> bool:
    if kind in {"IP-ASN", "SRC-IP-ASN"}:
        number = value.lstrip('0')
        return (value.isascii() and value.isdecimal() and 0 < len(number) <= 10
                and int(number) <= 4294967295)
    if kind in {"IP-SUFFIX", "SRC-IP-SUFFIX"}:
        try:
            ipaddress.ip_interface(value)
            return '/' in value
        except ValueError:
            return False
    if kind == "SRC-IP":
        try:
            (ipaddress.ip_network(value, strict=False) if '/' in value
             else ipaddress.ip_address(value))
            return True
        except ValueError:
            return False
    if kind in {"GEOIP", "SRC-GEOIP"}:
        return bool(re.fullmatch(r"[a-z]{2}", value, re.I))
    if kind == "GEOSITE":
        return bool(re.fullmatch(r"[a-z0-9_-]+(?:@[a-z0-9_-]+)?", value, re.I))
    if kind in {"UID", "DSCP"}:
        number = value.lstrip('0')
        return (value.isascii() and value.isdecimal() and len(number) <= 10
                and int(number or '0') <= (63 if kind == "DSCP" else 4294967295))
    if kind == "IN-USER":
        return all(re.fullmatch(r"[^/\s,<>]+", user) for user in value.split('/'))
    if kind == "MAC-ADDRESS":
        return bool(re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value, re.I))
    if kind == "HOSTNAME-TYPE":
        return value in {"IPv4", "IPv6", "DOMAIN", "SIMPLE"}
    if kind == "CELLULAR-RADIO":
        return value in {"GPRS", "Edge", "WCDMA", "HSDPA", "HSUPA", "CDMA1x",
                         "CDMAEVDORev0", "CDMAEVDORevA", "CDMAEVDORevB", "eHRPD",
                         "HRPD", "LTE", "NRNSA", "NR"}
    if kind == "CELLULAR-CARRIER":
        return bool(re.fullmatch(r"[0-9]{5,6}", value))
    if kind == "SUBNET":
        prefix, separator, target = value.partition(':')
        if not separator:
            return bool(value) and not any(c in value for c in '<>\r\n')
        if prefix == "TYPE":
            return target.upper() in {"WIFI", "WIRED", "CELLULAR"}
        if prefix == "ROUTER":
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                return False
        return (prefix in {"SSID", "BSSID"} and bool(target) and '<' not in target and '>' not in target
                or prefix == "MCCMNC" and bool(re.fullmatch(r"[0-9]{5,6}", target)))
    if kind == "NETWORK":
        return value.upper() in {"TCP", "UDP"}
    if kind == "PROTOCOL":
        return value in {"HTTP", "HTTPS", "TCP", "UDP", "QUIC", "STUN", "MTProto",
                         "DOH", "DOH3", "DOQ", "DOT", "DNS"}
    if kind == "IN-TYPE":
        return bool(re.fullmatch(r"[\w-]+(?:/[\w-]+)*", value, re.ASCII))
    return bool(re.fullmatch(r"[a-z0-9._-]+", value, re.I))


def _normalize_condition(expression: str, ignored_no_resolve: list[str] | None = None,
                         native_fields: bool = False) -> str | None:
    if not expression.startswith('(') or not expression.endswith(')'):
        return None
    try:
        fields = _fields(expression[1:-1], native_fields=native_fields)
    except ValueError:
        return None
    if len(fields) < 2:
        return None
    kind, value = fields[:2]
    kind = kind.upper()
    if not native_fields and kind in _REGEX and value.endswith(",no-resolve"):
        return None
    checked = value if native_fields else _field_value(value)
    if native_fields:
        options = {field for field in fields[2:] if field in {"src", "no-resolve"} and kind in _SOURCE_KINDS
                   or field == "no-resolve" and kind == "SRC-IP"}
    else:
        options = {field.lower() for field in fields[2:] if field.lower() != "src"}
        if "src" in fields[2:]:
            options.add("src")
    if options and (kind not in _SOURCE_KINDS and kind not in {*_SOURCE_KINDS.values(), "SRC-IP"}
                    or options - ({"no-resolve", "src"} if kind in _SOURCE_KINDS else {"no-resolve"})):
        return None
    source_kind = kind if "src" in options else None
    if source_kind:
        kind = _SOURCE_KINDS[kind]
    if "no-resolve" in options and kind.startswith("SRC-"):
        options.remove("no-resolve")
        if ignored_no_resolve is not None:
            ignored_no_resolve.append(kind)
    if kind in _LOGICAL:
        value = _normalize_logic(kind, value, ignored_no_resolve, native_fields)
        return f"({kind},{value})" if value is not None else None
    if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
        if not (_valid_domain(kind, checked) or kind == "DOMAIN" and _valid_domain("DOMAIN-SUFFIX", checked)):
            return None
    elif kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
        try:
            network = ipaddress.ip_network(checked, strict=False)
            if (kind == "IP-CIDR6" or source_kind == "IP-CIDR6") and network.version != 6:
                return None
            value = str(network)
        except ValueError:
            return None
    elif kind in _PORTS:
        if not _valid_port(value):
            return None
        if '/' in value:
            port_kind = "DST-PORT" if kind == "DEST-PORT" else kind
            return f"(OR,({','.join(f'({port_kind},{part})' for part in value.split('/'))}))"
        if value.startswith(('<', '>')):
            value = _port_comparison(value)
    elif kind in _SIMPLE:
        if not _valid_simple(kind, checked):
            return None
    elif kind in _REGEX:
        if not _valid_regex(kind, checked):
            return None
    elif kind in _PROCESS:
        if not checked or not native_fields and any(char in checked for char in '<>\r\n'):
            return None
    elif not value or kind not in _KINDS:
        return None
    return f"({kind},{value}{',no-resolve' if 'no-resolve' in options else ''})"


def _normalize_logic(kind: str, value: str, ignored_no_resolve: list[str] | None = None,
                     native_fields: bool = False) -> str | None:
    if not value.startswith('(') or not value.endswith(')'):
        return None
    if kind == "NOT":
        wrapped = value.startswith('((') and value.endswith('))')
        child = _normalize_condition(value[1:-1] if wrapped else value, ignored_no_resolve, native_fields)
        return f"({child})" if wrapped and child is not None else child
    try:
        children = _fields(value[1:-1], scope='children', native_fields=native_fields)
    except ValueError:
        return None
    if len(children) < 2:
        return None
    normalized = [_normalize_condition(child, ignored_no_resolve, native_fields) for child in children]
    if any(child is None for child in normalized):
        return None
    return f"({','.join(normalized)})"


def _has_process_name(kind: str, value: str, native_fields: bool = False) -> bool:
    if kind == "PROCESS-NAME":
        return True
    if kind not in _LOGICAL:
        return False
    if kind == "NOT":
        child = value[1:-1] if value.startswith("((") else value
        fields = _fields(child[1:-1], native_fields=native_fields)
        return _has_process_name(fields[0], fields[1], native_fields)
    return any(_has_process_name(*_fields(child[1:-1], native_fields=native_fields)[:2], native_fields)
               for child in _fields(value[1:-1], scope='children', native_fields=native_fields))


_YAML_ESCAPES = dict(zip('0abtnvfre\t "\'\\N_LP',
                         '\0\a\b\t\n\v\f\r\x1b\t "\'\\\x85\xa0  '))


def _yaml_quoted(scalar: str) -> tuple[str, int]:
    quote, decoded, index = scalar[0], [], 1
    while index < len(scalar):
        char = scalar[index]
        if char == quote:
            if quote == "'" and scalar.startswith("''", index):
                decoded.append("'")
                index += 2
                continue
            return ''.join(decoded), index + 1
        if quote == '"' and char == '\\':
            index += 1
            if index == len(scalar):
                break
            escape = scalar[index]
            if escape in _YAML_ESCAPES:
                char = _YAML_ESCAPES[escape]
            elif escape in 'xuU':
                width = {'x': 2, 'u': 4, 'U': 8}[escape]
                digits = scalar[index + 1:index + 1 + width]
                if len(digits) != width or any(digit not in '0123456789abcdefABCDEF' for digit in digits):
                    raise ValueError('invalid YAML payload')
                codepoint = int(digits, 16)
                if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                    raise ValueError('invalid YAML payload')
                char = chr(codepoint)
                index += width
            else:
                raise ValueError('invalid YAML payload')
        decoded.append(char)
        index += 1
    raise ValueError('invalid YAML payload')


def _check_yaml_source(source: str) -> None:
    # go-yaml 的原始字符范围仅用于解码前，escape 解码结果可以包含控制字符。
    for char in source:
        point = ord(char)
        if not (point in {9, 10, 13, 0x85} or 0x20 <= point <= 0x7E
                or 0xA0 <= point <= 0xD7FF or 0xE000 <= point <= 0xFFFD
                or 0x10000 <= point <= 0x10FFFF):
            raise ValueError('invalid YAML payload')


def _yaml_scalar(scalar: str) -> str:
    _check_yaml_source(scalar)
    scalar = scalar.strip(' \t')
    if not scalar or scalar[0] in '&*!|>[{?%@`' or scalar.startswith(('-', ':')):
        raise ValueError('invalid YAML payload')
    if scalar[0] in "'\"":
        value, end = _yaml_quoted(scalar)
        tail = scalar[end:].lstrip(' \t')
        if tail and not tail.startswith('#'):
            raise ValueError('invalid YAML payload')
        return value
    for index, char in enumerate(scalar):
        if char == '#' and (index == 0 or scalar[index - 1] in ' \t'):
            scalar = scalar[:index]
            break
        if char == ':' and (index + 1 == len(scalar) or scalar[index + 1] in ' \t'):
            raise ValueError('invalid YAML payload')
    return scalar.rstrip(' \t')


def _provider_header(line: str) -> str | None:
    line = line.lstrip(' ')
    if not line:
        return None
    if line[0] in "'\"":
        key, end = _yaml_quoted(line)
        rest = line[end:].lstrip(' \t')
        if not rest.startswith(':'):
            return None
    else:
        key, separator, rest = line.partition(':')
        if not separator:
            return None
        key = key.rstrip(' \t')
        rest = ':' + rest
    if key not in {'payload', 'rules'}:
        return None
    _check_yaml_source(line)
    if len(rest) > 1 and rest[1] not in ' \t':
        raise ValueError('invalid YAML payload')
    tail = rest[1:].lstrip(' \t')
    if tail and not tail.startswith('#'):
        raise ValueError('invalid YAML payload')
    return key


def _without_comment(line: str) -> str:
    try:
        _, end = _source_parts(line)
    except ValueError:
        return line
    return line[:end].rstrip()


def _has_regex_field(line: str) -> bool:
    head = re.match(r'''^\s*(?:-\s+['"]?)?([a-z-]+),''', line, re.I)
    if head is None:
        return False
    kind = head[1].upper()
    return kind in _REGEX or kind in _LOGICAL and bool(re.search(
        r"\(\s*(?:DOMAIN-REGEX|URL-REGEX|PROCESS-(?:NAME|PATH)-REGEX),", line, re.I
    ))


def parse(text: str, *, purpose: str, ignore_policy: bool = False) -> tuple[list[Rule], list[str]]:
    if purpose not in {"block", "direct", "proxy"}:
        raise ValueError(f"invalid purpose: {purpose}")
    lines = text.removeprefix('\ufeff').split('\n')
    records = []
    in_payload = False
    for source in lines:
        source = source.removesuffix('\r')
        line = source.strip(' \t')
        if not line or line.startswith(('#', ';', '//')):
            records.append((None, False, None, None))
            continue
        try:
            if any(char in source for char in '\0\r\v\f\x85\u2028\u2029'):
                raise ValueError('unsupported physical line separator')
            header = _provider_header(source) if not source.startswith('\t') else None
            if header:
                in_payload = True
                records.append((None, False, None, None))
                continue
            yaml_rule = in_payload and source.lstrip(' \t').startswith('-')
            if line.startswith('-'):
                item = re.fullmatch(r" *- +([^ \t].*)", source)
                if not yaml_rule or item is None:
                    raise ValueError('invalid YAML payload')
                line = _yaml_scalar(item[1])
                parts = _native_parts(line)
            elif in_payload and source.startswith((' ', '\t')):
                raise ValueError('invalid YAML payload')
            else:
                in_payload = False
                parts, end = _source_parts(line)
                line = line[:end].rstrip()
            records.append((line, yaml_rule, parts, None))
        except ValueError as exc:
            records.append((line, False, None, str(exc)))
    opening_tags, html_lines = {}, set()
    for number, (line, _, _, _) in enumerate(records, 1):
        if line is None or line.lstrip().startswith(('#', ';', '//', '!')):
            continue
        if _has_regex_field(line):
            continue
        if re.match(r"^\s*<\s*!doctype\b", line, re.I):
            return [], [f"line {number}: HTML document"]
        for tag in re.finditer(r"(?<!\(\?)<\s*(/?)\s*([a-z][\w:-]*)\b[^>]*>", line, re.I):
            name = tag[2].lower()
            if tag[1] and name in opening_tags:
                opening = opening_tags[name].pop()
                if not opening_tags[name]:
                    del opening_tags[name]
                if opening != number:
                    if name == 'html':
                        return [], [f"line {opening}: HTML document"]
                    html_lines.update(range(opening, number + 1))
            elif not tag[1] and not tag[0].endswith('/>'):
                if name != 'html' and 'html' in opening_tags:
                    return [], [f"line {opening_tags['html'][0]}: HTML document"]
                opening_tags.setdefault(name, []).append(number)
    if html_lines and all(number in html_lines or not line.strip() or
                          line.lstrip().startswith(('#', ';', '//', '!'))
                          for number, line in enumerate(lines, 1)):
        return [], [f"line {min(html_lines)}: HTML document"]
    rules, warnings = [], []
    for number, (line, yaml_rule, parts, error) in enumerate(records, 1):
        if error is not None:
            warnings.append(f"line {number}: {error}")
            continue
        if line is None:
            continue
        if not _has_regex_field(line) and re.search(
            r"(?<!\(\?)<\s*(?:/?[a-z][\w:-]*(?:\s[^>]*|/?)>|!doctype\b|!--)", line, re.I
        ):
            warnings.append(f"line {number}: HTML markup")
            continue
        if number in html_lines:
            continue
        if re.fullmatch(r"\[[\w -]+\]", line):
            continue
        if line.startswith(('||', '@@||')) and '$' in line:
            warnings.append(f"line {number}: conditional ABP rule")
            continue
        host_parts = line.split()
        if host_parts and host_parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
            if purpose != "block":
                warnings.append(f"line {number}: hosts entry is block-only")
                continue
            for domain in host_parts[1:]:
                if domain.startswith('#'):
                    break
                if _valid_domain("DOMAIN", domain):
                    rules.append(Rule("DOMAIN", domain))
                else:
                    warnings.append(f"line {number}: invalid hosts domain {domain}")
            continue
        allow = line.startswith('@@')
        options = ()
        source_kind = ""
        abp = re.fullmatch(r"(?:@@)?\|\|([^|^/$]+)\^", line)
        bare_network = None
        if '/' in line and ',' not in line:
            try:
                bare_network = ipaddress.ip_network(line, strict=False)
            except ValueError:
                pass
        if abp:
            kind, value, action = "DOMAIN-SUFFIX", abp[1], ("" if allow else "REJECT")
        elif bare_network is not None:
            kind = "IP-CIDR6" if bare_network.version == 6 else "IP-CIDR"
            value, action = str(bare_network), ""
        elif _valid_domain("DOMAIN-SUFFIX" if line.startswith('.') else "DOMAIN", line.removeprefix('.')):
            kind, value, action = ("DOMAIN-SUFFIX" if line.startswith('.') else "DOMAIN"), line.removeprefix('.'), ""
        else:
            if len(parts) < 2:
                warnings.append(f"line {number}: invalid rule")
                continue
            kind, value = parts[:2]
            if not yaml_rule:
                value = _field_value(value)
            kind = {
                "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX",
                "HOST-WILDCARD": "DOMAIN-WILDCARD", "HOST-KEYWORD": "DOMAIN-KEYWORD",
                "IP6-CIDR": "IP-CIDR6",
            }.get(kind.upper(), kind.upper())
            if yaml_rule:
                params = parts[2:]
                if kind in _SOURCE_KINDS and 'src' in params:
                    source_kind = kind
                options = tuple(field for field in params if field == 'no-resolve'
                                and kind in {*_SOURCE_KINDS, 'SRC-IP'})
                action = ''
            else:
                if kind in _SOURCE_KINDS and len(parts) > 3:
                    for field in parts[3:]:
                        if field.lower() == 'src' and field != 'src':
                            warnings.append(f"line {number}: unsupported src option {field}")
                    parts = [*parts[:3], *(field for field in parts[3:]
                                           if field.lower() != 'src' or field == 'src')]
                if kind in _SOURCE_KINDS:
                    if "src" in parts[3:]:
                        source_kind = kind
                        parts = [*parts[:3], *(field for field in parts[3:] if field != "src")]
                    elif parts[2:3] == ["src"] and all(field in {"src", "no-resolve"} for field in parts[2:]):
                        warnings.append(f"line {number}: ambiguous src policy or option")
                        continue
                if kind in _PORTS and len(parts) > 3:
                    end = 2
                    while end < len(parts) - 1 and _valid_port(parts[end]):
                        end += 1
                    if end > 2:
                        value = '/'.join(parts[1:end])
                        parts = [parts[0], value, *parts[end:]]
                if any(field.lower() == "extended-matching" for field in parts[2:]):
                    warnings.append(f"line {number}: unsupported ruleset option extended-matching")
                    continue
                recognized_options = {"no-resolve"} | (
                    _QX_INTERFACE_OPTIONS if kind in _QX_INTERFACE_KINDS and not source_kind else set()
                )
                options = tuple(field.lower() for field in parts[2:]
                                if field.lower() in recognized_options)
                actions = [field.upper() for field in parts[2:]
                           if field.lower() not in recognized_options]
                if len(actions) > 1:
                    warnings.append(f"line {number}: unexpected fields")
                    continue
                action = actions[0] if actions else ""
                if action == "LIST":
                    action = ""
        if kind not in _KINDS:
            warnings.append(f"line {number}: unknown type {kind}")
            continue
        if source_kind:
            kind = _SOURCE_KINDS[source_kind]
        if kind == "SRC-IP" and '/' in value:
            kind = "SRC-IP-CIDR"
        if "no-resolve" in options and kind in {"SRC-IP", "SRC-IP-CIDR", "SRC-IP-SUFFIX", "SRC-GEOIP", "SRC-IP-ASN"}:
            warnings.append(f"line {number}: unsupported no-resolve for {kind}")
            options = tuple(option for option in options if option != "no-resolve")
        if "no-resolve" in options and kind not in {"IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "GEOIP", "IP-ASN"}:
            warnings.append(f"line {number}: unsupported no-resolve for {kind}")
            continue
        if kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
            try:
                network = ipaddress.ip_network(value, strict=False)
                if (kind == "IP-CIDR6" or source_kind == "IP-CIDR6") and network.version != 6:
                    raise ValueError("wrong address family")
                value = str(network)
            except ValueError:
                warnings.append(f"line {number}: invalid CIDR {value}")
                continue
        elif kind in _PORTS:
            if not _valid_port(value):
                warnings.append(f"line {number}: invalid port {value}")
                continue
            if '/' in value:
                port_kind = "DST-PORT" if kind == "DEST-PORT" else kind
                value = '(' + ','.join(f"({port_kind},{part})" for part in value.split('/')) + ')'
                kind = "OR"
            elif value.startswith(('<', '>')):
                value = _port_comparison(value)
        elif kind == "SRC-IP":
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                warnings.append(f"line {number}: invalid IP address {value}")
                continue
        elif kind in _SIMPLE:
            if not _valid_simple(kind, value):
                warnings.append(f"line {number}: invalid {kind} {value}")
                continue
        elif kind in _PROCESS:
            if not value or not yaml_rule and (any(char in value for char in '\r\n') or (
                kind not in _REGEX and any(char in value for char in '<>')
            )):
                warnings.append(f"line {number}: invalid value {value}")
                continue
            if kind in _REGEX and not _valid_regex(kind, value):
                warnings.append(f"line {number}: invalid {kind} {value}")
                continue
        elif kind in _LOGICAL:
            ignored_no_resolve = []
            normalized = _normalize_logic(kind, value, ignored_no_resolve, yaml_rule)
            if normalized is None:
                warnings.append(f"line {number}: invalid logical expression {value}")
                continue
            warnings.extend(f"line {number}: unsupported no-resolve for {child_kind}"
                            for child_kind in ignored_no_resolve)
            value = normalized
        elif not (_valid_domain(kind, value) or kind == "DOMAIN" and _valid_domain("DOMAIN-SUFFIX", value)):
            warnings.append(f"line {number}: invalid domain {value}")
            continue
        if action and not ignore_policy and not (purpose == "block" and action in _BLOCK_ACTIONS or
                           action == purpose.upper() or
                           purpose in {"direct", "proxy"} and
                           action not in _BLOCK_ACTIONS | {"DIRECT", "PROXY"} and
                           not action.startswith("REJECT")):
            warnings.append(f"line {number}: incompatible action {action}")
        else:
            rules.append(Rule(kind, value, options, allow=allow,
                              literal_process=yaml_rule and _has_process_name(kind, value, yaml_rule),
                              native_fields=yaml_rule and kind in _LOGICAL))
    return rules, warnings


def parse_whitelist(text: str) -> list[Rule]:
    parsed, messages = parse(text, purpose="block", ignore_policy=True)
    supported = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
                 "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP", "IP-ASN", "GEOIP",
                 "SRC-IP-ASN", "SRC-GEOIP", "IP-SUFFIX", "SRC-IP-SUFFIX"}
    whitelist = [Rule(rule.kind, rule.value, literal_process=rule.literal_process,
                      native_fields=rule.native_fields) for rule in parsed if rule.kind in supported]
    if not parsed and not messages:
        raise ValueError("no rules")
    if not whitelist and messages:
        raise ValueError(messages[0])
    for message in messages:
        warnings.warn(message, stacklevel=2)
    return whitelist


def exclude_covered(rules: Iterable[Rule], whitelist: Iterable[Rule]) -> list[Rule]:
    exact, suffixes, keywords, wildcards, typed = set(), set(), set(), set(), set()
    networks = {"src": set(), "dst": set()}
    for entry in whitelist:
        if entry.kind == "DOMAIN":
            exact.add(entry.value)
        elif entry.kind == "DOMAIN-SUFFIX":
            suffixes.add(entry.value)
        elif entry.kind == "DOMAIN-KEYWORD":
            keywords.add(entry.value)
        elif entry.kind == "DOMAIN-WILDCARD":
            wildcards.add(entry.value)
        elif entry.kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP"}:
            direction = "src" if entry.kind.startswith("SRC-") else "dst"
            networks[direction].add(ipaddress.ip_network(entry.value, strict=False))
        elif entry.kind in {"IP-ASN", "GEOIP", "IP-SUFFIX", "SRC-IP-ASN", "SRC-GEOIP", "SRC-IP-SUFFIX"}:
            typed.add((entry.kind, entry.value.upper()))
    plain_wildcards = [pattern for pattern in wildcards if '[' not in pattern]
    kept = []
    for rule in rules:
        if rule.allow:
            kept.append(rule)
            continue
        kind, value = rule.kind, rule.value
        if kind == "DOMAIN" or (kind == "DOMAIN-WILDCARD" and not any(c in value for c in "*?[]")):
            covered = (value in exact or _has_parent(value, suffixes) or
                       any(keyword in value for keyword in keywords) or
                       any(fnmatchcase(value, pattern) for pattern in plain_wildcards))
        elif kind == "DOMAIN-SUFFIX":
            covered = _has_parent(value, suffixes) or any(keyword in value for keyword in keywords)
        elif kind == "DOMAIN-KEYWORD":
            covered = any(keyword in value for keyword in keywords)
        elif kind == "DOMAIN-WILDCARD":
            tail = value[max(value.rfind(char) for char in "*?]") + 1:]
            covered = (value in wildcards or
                       tail.startswith('.') and _has_parent(tail[1:], suffixes) or
                       any(keyword in segment for keyword in keywords
                           for segment in re.split(r"\*|\?|\[[a-z0-9-]+\]", value)))
        elif kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP"}:
            direction = "src" if kind.startswith("SRC-") else "dst"
            covered = False
            if networks[direction]:
                network = ipaddress.ip_network(value, strict=False)
                while True:
                    if network in networks[direction]:
                        covered = True
                        break
                    if network.prefixlen == 0:
                        break
                    network = network.supernet()
        else:
            covered = (kind, value.upper()) in typed
        if not covered:
            kept.append(rule)
    return kept


def _has_parent(domain: str, parents: set[str]) -> bool:
    while domain:
        if domain in parents:
            return True
        domain = domain.partition('.')[2]
    return False


def normalize(rules: Iterable[Rule]) -> list[Rule]:
    unique = set(rules)
    suffixes = {}
    for rule in unique:
        if rule.kind == "DOMAIN-SUFFIX":
            suffixes.setdefault((rule.allow, rule.options), set()).add(rule.value)
    keywords = {}
    for rule in unique:
        if rule.kind == "DOMAIN-KEYWORD":
            keywords.setdefault((rule.allow, rule.options), set()).add(rule.value)
    kept = []
    for rule in unique:
        if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-WILDCARD"}:
            candidate = rule.value
            if rule.kind == "DOMAIN-WILDCARD":
                last_wildcard = max(candidate.rfind(char) for char in '*?]')
                tail = candidate[last_wildcard + 1:]
                candidate = tail.partition('.')[2]
            group = suffixes.get((rule.allow, rule.options), set())
            while candidate:
                if candidate in group and (rule.kind != "DOMAIN-SUFFIX" or candidate != rule.value):
                    break
                candidate = candidate.partition('.')[2]
            if candidate:
                continue
        if rule.kind == "DOMAIN-KEYWORD":
            group = keywords[(rule.allow, rule.options)]
            if any(rule.value[start:end] in group
                   for start in range(len(rule.value))
                   for end in range(start + 1, len(rule.value) + 1)
                   if end - start < len(rule.value)):
                continue
        kept.append(rule)
    networks = {}
    others = []
    for rule in kept:
        if rule.kind in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
            network = ipaddress.ip_network(rule.value, strict=False)
            kind = "IP-CIDR6" if rule.kind == "IP-CIDR" and network.version == 6 else rule.kind
            networks.setdefault((kind, network.version, rule.options, rule.allow, rule.literal_process, rule.native_fields), []).append(network)
        else:
            others.append(rule)
    for (kind, _, options, allow, literal_process, native_fields), group in networks.items():
        others.extend(Rule(kind, str(network), options, allow, literal_process, native_fields)
                      for network in ipaddress.collapse_addresses(group))
    return sorted(others, key=lambda rule: (rule.kind, rule.value, rule.options, rule.allow, rule.literal_process, rule.native_fields))
