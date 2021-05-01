import os
from . import _undname  # automatically resolve and load shared library (_undame.pyd or _undame.so)

UNDNAME_COMPLETE = 0x0000
UNDNAME_NO_LEADING_UNDERSCORES = 0x0001  # Don't show __ in calling convention
UNDNAME_NO_MS_KEYWORDS = 0x0002  # Don't show calling convention at all
UNDNAME_NO_FUNCTION_RETURNS = 0x0004  # Don't show function/method return value
UNDNAME_NO_ALLOCATION_MODEL = 0x0008
UNDNAME_NO_ALLOCATION_LANGUAGE = 0x0010
UNDNAME_NO_MS_THISTYPE = 0x0020
UNDNAME_NO_CV_THISTYPE = 0x0040
UNDNAME_NO_THISTYPE = 0x0060
UNDNAME_NO_ACCESS_SPECIFIERS = 0x0080  # Don't show access specifier public/protected/private
UNDNAME_NO_THROW_SIGNATURES = 0x0100
UNDNAME_NO_MEMBER_TYPE = 0x0200  # Don't show static/virtual specifier
UNDNAME_NO_RETURN_UDT_MODEL = 0x0400
UNDNAME_32_BIT_DECODE = 0x0800
UNDNAME_NAME_ONLY = 0x1000  # Only report the variable/method name
UNDNAME_NO_ARGUMENTS = 0x2000  # Don't show method arguments
UNDNAME_NO_SPECIAL_SYMS = 0x4000
UNDNAME_NO_COMPLEX_TYPE = 0x8000


def undname(name, flags = UNDNAME_NAME_ONLY):

    if name.startswith("?"):
        name = _undname.undname(name, flags)
    elif name.startswith("_") or name.startswith("@"):
        name = name.rsplit('@', 1)[0][1:]

    return name
