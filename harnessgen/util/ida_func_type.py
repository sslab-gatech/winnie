import json
import os
import typing

from idautils import Segments, Functions
from idc import get_segm_start, get_segm_end, get_func_name
import idaapi


def serialize(tif: idaapi.tinfo_t) -> typing.Union[dict, None]:
    fi = idaapi.func_type_data_t()
    if not tif.get_func_details(fi):
        return None

    args = [{"type": str(arg.type), "name": arg.name} for arg in fi]

    return ({
        'args': args,
        'ret_type': str(fi.rettype),
        'cc': '__stdcall' if fi.cc == idaapi.CM_CC_STDCALL else '__cdecl'
    })


def main():
    idaapi.auto_wait()
    base = idaapi.get_imagebase()
    tif = idaapi.tinfo_t()

    f = open(os.environ.get("DESTPATH", "functype_"), 'w')

    for ea in Segments():
        # only code segment
        if idaapi.segtype(ea) != idaapi.SEG_CODE:
            continue

        for fva in Functions(get_segm_start(ea), get_segm_end(ea)):
            func_name = get_func_name(fva)
            has_type = idaapi.get_tinfo(tif, fva) or idaapi.guess_tinfo(tif, fva)

            if not has_type:
                continue

            info = serialize(tif)
            if info is None:
                continue

            print(hex(fva-base)[:-1], "|", func_name, "|", tif, "|", len(info['args']))
            f.write("0x%x|%s|%s\n" % (fva-base, func_name, json.dumps(info)))

    f.close()
    idaapi.qexit(0)


main()
