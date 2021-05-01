from io import BytesIO

from construct import *

_strarray = "names" / GreedyRange(CString(encoding = "utf8"))


class StringArrayAdapter(Adapter):

    def _encode(self, obj, context, path):
        return _strarray._build(BytesIO(obj), context, path)

    def _decode(self, obj, context, path):
        return _strarray._parse(BytesIO(obj), context, path)


def GUID(name):
    return name / Struct(
        "Data1" / Int32ul,
        "Data2" / Int16ul,
        "Data3" / Int16ul,
        "Data4" / Bytes(8),
    )


Info = "Info" / Struct(
    "Version" / Int32ul,
    "TimeDateStamp" / Int32ul,
    "Age" / Int32ul,
    GUID("GUID"),
    "cbNames" / Int32ul,
    "names" / StringArrayAdapter(Bytes(lambda ctx: ctx.cbNames)),
)


def parse_stream(stream):
    return Info.parse_stream(stream)


def parse(data):
    return Info.parse(data)
