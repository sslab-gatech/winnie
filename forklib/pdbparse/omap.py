#!/usr/bin/env python

from construct import *
from bisect import bisect

OMAP_ENTRY = "OmapFromSrc" / Struct(
    "From" / Int32ul,
    "To" / Int32ul,
)

OMAP_ENTRIES = GreedyRange(OMAP_ENTRY)


class Omap(object):

    def __init__(self, omapstream):
        self.omap = OMAP_ENTRIES.parse(omapstream)

        self._froms = None

    def remap(self, address):
        if not self._froms:
            self._froms = [o.From for o in self.omap]

        pos = bisect(self._froms, address)
        if self._froms[pos] != address:
            pos = pos - 1

        if self.omap[pos].To == 0:
            return self.omap[pos].To
        else:
            return self.omap[pos].To + (address - self.omap[pos].From)
