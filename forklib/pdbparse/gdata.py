# Python 2 and 3

from construct import *

gsym = Struct(
    "leaf_type" / Int16ul, "data" / Switch(
        lambda ctx: ctx.leaf_type, {
            0x110E:
            "data_v3" / Struct(
                "symtype" / Int32ul,
                "offset" / Int32ul,
                "segment" / Int16ul,
                "name" / CString(encoding = "utf8"),
            ),
            0x1009:
            "data_v2" / Struct(
                "symtype" / Int32ul,
                "offset" / Int32ul,
                "segment" / Int16ul,
                "name" / PascalString(lengthfield = "length" / Int8ul, encoding = "utf8"),
            ),
        }))

GlobalsData = "globals" / GreedyRange(
    Struct(
        "length" / Int16ul,
        "symbol" / RestreamData(Bytes(lambda ctx: ctx.length), gsym),
    ))


def parse(data):
    con = GlobalsData.parse(data)
    return merge_structures(con)


def parse_stream(stream):
    con = GlobalsData.parse_stream(stream)
    return merge_structures(con)


def merge_structures(con):
    new_cons = []
    for sym in con:
        sym_dict = {'length': sym.length, 'leaf_type': sym.symbol.leaf_type}
        if sym.symbol.data:
            sym_dict.update({
                'symtype': sym.symbol.data.symtype,
                'offset': sym.symbol.data.offset,
                'segment': sym.symbol.data.segment,
                'name': sym.symbol.data.name
            })
        new_cons.append(Container(sym_dict))
    result = ListContainer(new_cons)
    return result
