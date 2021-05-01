#!/usr/bin/env python

from construct import *

from pdbparse.info import GUID
from pdbparse.pe import IMAGE_SECTION_HEADER

CV_RSDS_HEADER = "CV_RSDS" / Struct(
    "Signature" / Const(b"RSDS", Bytes(4)),
    GUID("GUID"),
    "Age" / Int32ul,
    "Filename" / CString(encoding = "utf8"),
)

CV_NB10_HEADER = "CV_NB10" / Struct(
    "Signature" / Const(b"NB10", Bytes(4)),
    "Offset" / Int32ul,
    "Timestamp" / Int32ul,
    "Age" / Int32ul,
    "Filename" / CString(encoding = "utf8"),
)

DebugDirectoryType = "Type" / Enum(
    Int32ul,
    IMAGE_DEBUG_TYPE_UNKNOWN = 0,
    IMAGE_DEBUG_TYPE_COFF = 1,
    IMAGE_DEBUG_TYPE_CODEVIEW = 2,
    IMAGE_DEBUG_TYPE_FPO = 3,
    IMAGE_DEBUG_TYPE_MISC = 4,
    IMAGE_DEBUG_TYPE_EXCEPTION = 5,
    IMAGE_DEBUG_TYPE_FIXUP = 6,
    IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7,
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8,
    IMAGE_DEBUG_TYPE_BORLAND = 9,
    IMAGE_DEBUG_TYPE_RESERVED = 10,
    _default_ = "IMAGE_DEBUG_TYPE_UNKNOWN",
)

DebugMiscType = "Type" / Enum(
    Int32ul,
    IMAGE_DEBUG_MISC_EXENAME = 1,
    _default_ = Pass,
)

IMAGE_SEPARATE_DEBUG_HEADER = "IMAGE_SEPARATE_DEBUG_HEADER" / Struct(
    "Signature" / Const(b"DI", Bytes(2)),
    "Flags" / Int16ul,
    "Machine" / Int16ul,
    "Characteristics" / Int16ul,
    "TimeDateStamp" / Int16ul,
    "CheckSum" / Int16ul,
    "ImageBase" / Int16ul,
    "SizeOfImage" / Int16ul,
    "NumberOfSections" / Int16ul,
    "ExportedNamesSize" / Int16ul,
    "DebugDirectorySize" / Int16ul,
    "SectionAlignment" / Int16ul,
    Array(2, "Reserved" / Int32ul),
)

IMAGE_DEBUG_DIRECTORY = "IMAGE_DEBUG_DIRECTORY" / Struct(
    "Characteristics" / Int32ul,
    "TimeDateStamp" / Int32ul,
    "MajorVersion" / Int16ul,
    "MinorVersion" / Int16ul,
    DebugDirectoryType,
    "SizeOfData" / Int32ul,
    "AddressOfRawData" / Int32ul,
    "PointerToRawData" / Int32ul,
    "Data" / Pointer(lambda ctx: ctx.PointerToRawData, Bytes(lambda ctx: ctx.SizeOfData)),
)

IMAGE_DEBUG_MISC = "IMAGE_DEBUG_MISC" / Struct(
    DebugMiscType,
    "Length" / Int32ul,
    "Unicode" / Byte,
    Array(3, "Reserved" / Byte),
    "Strings" / RestreamData(
        Bytes(lambda ctx: ctx.Length - 12),
        GreedyRange(CString(encoding = "utf8")),
    ),
)

IMAGE_FUNCTION_ENTRY = "IMAGE_FUNCTION_ENTRY" / Struct(
    "StartingAddress" / Int32ul,
    "EndingAddress" / Int32ul,
    "EndOfPrologue" / Int32ul,
)

DbgFile = "DbgFile" / Struct(
    IMAGE_SEPARATE_DEBUG_HEADER,
    Array(lambda ctx: ctx.IMAGE_SEPARATE_DEBUG_HEADER.NumberOfSections, IMAGE_SECTION_HEADER),
    "ExportedNames" / RestreamData(
        Bytes(lambda ctx: ctx.IMAGE_SEPARATE_DEBUG_HEADER.ExportedNamesSize),
        GreedyRange(CString(encoding = "utf8")),
    ),
    Array(lambda ctx: ctx.IMAGE_SEPARATE_DEBUG_HEADER.DebugDirectorySize / IMAGE_DEBUG_DIRECTORY.sizeof(),
          IMAGE_DEBUG_DIRECTORY))
