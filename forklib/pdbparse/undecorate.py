#!/usr/bin/env python

prefixes = "__imp__", "__imp_@", "__imp_", "_", "@", "\x7F"


def undecorate(name):
    stack = -1
    conv = "UNDEFINED"
    orig_name = name
    for p in prefixes:
        if name.startswith(p):
            name = name[len(p):]
            break

    if name.startswith("@@") or name.startswith("?"):
        name = orig_name
    else:
        name_parts = name.split("@")
        if len(name_parts) == 2:
            try:
                stack = int(name_parts[1])
                name = name_parts[0]
            except ValueError:
                stack = -1
                name = orig_name

    if len(p) == 1:
        if p == "_":
            conv = "FASTCALL"
        elif p == "@":
            if stack == -1: conv = "CDECL"
            else: conv = "STDCALL"
    return (name, stack, conv)
