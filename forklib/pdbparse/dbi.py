#!/usr/bin/env python

# Python 2 and 3: forward-compatible
from builtins import range
# Python 2 and 3
from io import BytesIO

from construct import *

_ALIGN = 4


def get_parsed_size(tp, con):
    return len(tp.build(con))


def SymbolRange(name):
    return name / Struct(
        "section" / Int16sl,
        Padding(2),
        "offset" / Int32sl,
        "size" / Int32sl,
        "flags" / Int32ul,
        "module" / Int16sl,
        Padding(2),
        "dataCRC" / Int32ul,
        "relocCRC" / Int32ul,
    )


DBIHeader = "DBIHeader" / Struct(
    "magic" / Const(b"\xFF\xFF\xFF\xFF", Bytes(4)),  # 0
    "version" / Int32ul,  # 4
    "age" / Int32ul,  # 8
    "gssymStream" / Int16sl,  # 12
    "vers" / Int16ul,  # 14
    "pssymStream" / Int16sl,  # 16
    "pdbver" / Int16ul,  # 18
    "symrecStream" / Int16sl,  # stream containing global symbols   # 20
    "pdbver2" / Int16ul,  # 22
    "module_size" / Int32ul,  # total size of DBIExHeaders            # 24
    "secconSize" / Int32ul,  # 28
    "secmapSize" / Int32ul,  # 32
    "filinfSize" / Int32ul,  # 36
    "tsmapSize" / Int32ul,  # 40
    "mfcIndex" / Int32ul,  # 44
    "dbghdrSize" / Int32ul,  # 48
    "ecinfoSize" / Int32ul,  # 52
    "flags" / Int16ul,  # 56
    "Machine" / Enum(
        Int16ul,  # 58
        IMAGE_FILE_MACHINE_UNKNOWN = 0x0000,
        IMAGE_FILE_MACHINE_I386 = 0x014c,
        IMAGE_FILE_MACHINE_R3000 = 0x0162,
        IMAGE_FILE_MACHINE_R4000 = 0x0166,
        IMAGE_FILE_MACHINE_R10000 = 0x0168,
        IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169,
        IMAGE_FILE_MACHINE_ALPHA = 0x0184,
        IMAGE_FILE_MACHINE_SH3 = 0x01a2,
        IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
        IMAGE_FILE_MACHINE_SH3E = 0x01a4,
        IMAGE_FILE_MACHINE_SH4 = 0x01a6,
        IMAGE_FILE_MACHINE_SH5 = 0x01a8,
        IMAGE_FILE_MACHINE_ARM = 0x01c0,
        IMAGE_FILE_MACHINE_THUMB = 0x01c2,
        IMAGE_FILE_MACHINE_ARMNT = 0x01c4,
        IMAGE_FILE_MACHINE_AM33 = 0x01d3,
        IMAGE_FILE_MACHINE_POWERPC = 0x01f0,
        IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
        IMAGE_FILE_MACHINE_IA64 = 0x0200,
        IMAGE_FILE_MACHINE_MIPS16 = 0x0266,
        IMAGE_FILE_MACHINE_ALPHA64 = 0x0284,
        IMAGE_FILE_MACHINE_AXP64 = 0x0284,
        IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,
        IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,
        IMAGE_FILE_MACHINE_TRICORE = 0x0520,
        IMAGE_FILE_MACHINE_CEF = 0x0cef,
        IMAGE_FILE_MACHINE_EBC = 0x0ebc,
        IMAGE_FILE_MACHINE_AMD64 = 0x8664,
        IMAGE_FILE_MACHINE_M32R = 0x9041,
        IMAGE_FILE_MACHINE_CEE = 0xc0ee,
    ),
    "resvd" / Int32ul,  # 60
)

DBIExHeader = "DBIExHeader" / Struct(
    "opened" / Int32ul,
    SymbolRange("range"),
    "flags" / Int16ul,
    "stream" / Int16sl,
    "symSize" / Int32ul,
    "oldLineSize" / Int32ul,
    "lineSize" / Int32ul,
    "nSrcFiles" / Int16sl,
    Padding(2),
    "offsets" / Int32ul,
    "niSource" / Int32ul,
    "niCompiler" / Int32ul,
    "modName" / CString(encoding = "utf8"),
    "objName" / CString(encoding = "utf8"),
)

DbiDbgHeader = "DbiDbgHeader" / Struct(
    "snFPO" / Int16sl,
    "snException" / Int16sl,
    "snFixup" / Int16sl,
    "snOmapToSrc" / Int16sl,
    "snOmapFromSrc" / Int16sl,
    "snSectionHdr" / Int16sl,
    "snTokenRidMap" / Int16sl,
    "snXdata" / Int16sl,
    "snPdata" / Int16sl,
    "snNewFPO" / Int16sl,
    "snSectionHdrOrig" / Int16sl,
)

sstFileIndex = "sstFileIndex" / Struct(
    "cMod" / Int16ul,
    "cRef" / Int16ul,
)


def parse_stream(stream):
    pos = 0
    dbihdr = DBIHeader.parse_stream(stream)
    pos += get_parsed_size(DBIHeader, dbihdr)
    stream.seek(pos)
    dbiexhdr_data = stream.read(dbihdr.module_size)

    # sizeof() is broken on CStrings for construct, so
    # this ugly ugly hack is necessary
    dbiexhdrs = []
    while dbiexhdr_data:
        dbiexhdrs.append(DBIExHeader.parse(dbiexhdr_data))
        sz = get_parsed_size(DBIExHeader, dbiexhdrs[-1])
        if sz % _ALIGN != 0:
            sz = sz + (_ALIGN - (sz % _ALIGN))
        dbiexhdr_data = dbiexhdr_data[sz:]

    # "Section Contribution"
    stream.seek(dbihdr.secconSize, 1)
    # "Section Map"
    stream.seek(dbihdr.secmapSize, 1)
    #
    # see: http://pierrelib.pagesperso-orange.fr/exec_formats/MS_Symbol_Type_v1.0.pdf
    # the contents of the filinfSize section is a 'sstFileIndex'
    #
    # "File Info"
    end = stream.tell() + dbihdr.filinfSize
    fileIndex = sstFileIndex.parse_stream(stream)
    modStart = Array(fileIndex.cMod, Int16ul).parse_stream(stream)
    cRefCnt = Array(fileIndex.cMod, Int16ul).parse_stream(stream)
    NameRef = Array(fileIndex.cRef, Int32ul).parse_stream(stream)
    modules = []  # array of arrays of files
    files = []  # array of files (non unique)
    Names = stream.read(end - stream.tell())
    for i in range(0, fileIndex.cMod):
        these = []
        for j in range(modStart[i], modStart[i] + cRefCnt[i]):
            Name = "Name" / CString(encoding = "utf8").parse(Names[NameRef[j]:])
            files.append(Name)
            these.append(Name)
        modules.append(these)

    # stream.seek(dbihdr.filinfSize, 1)
    # "TSM"
    stream.seek(dbihdr.tsmapSize, 1)
    # "EC"
    stream.seek(dbihdr.ecinfoSize, 1)
    # The data we really want
    dbghdr = DbiDbgHeader.parse_stream(stream)

    return Container(
        DBIHeader = dbihdr,
        DBIExHeaders = ListContainer(dbiexhdrs),
        DBIDbgHeader = dbghdr,
        modules = modules,
        files = files)


def parse(data):
    return parse_stream(BytesIO(data))
