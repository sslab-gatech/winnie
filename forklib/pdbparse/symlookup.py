import os
from bisect import bisect_right
from operator import itemgetter, attrgetter

import pdbparse


class DummyOmap(object):

    def remap(self, addr):
        return addr


class Lookup(object):

    def __init__(self, mods):
        self.addrs = {}
        self._cache = {}

        not_found = []

        for pdbname, base in mods:
            pdbbase = ".".join(os.path.basename(pdbname).split('.')[:-1])
            if not os.path.exists(pdbname):
                print("WARN: %s not found" % pdbname)
                not_found.append((base, pdbbase))
                continue

            # print ("Loading symbols for %s..." % pdbbase)
            try:
                # Do this the hard way to avoid having to load
                # the types stream in mammoth PDB files
                pdb = pdbparse.parse(pdbname, fast_load = True)
                pdb.STREAM_DBI.load()
                pdb._update_names()
                pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
                if pdb.STREAM_GSYM.size:
                    pdb.STREAM_GSYM.load()
                pdb.STREAM_SECT_HDR = pdb.STREAM_SECT_HDR.reload()
                pdb.STREAM_SECT_HDR.load()
                # These are the dicey ones
                pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
                pdb.STREAM_OMAP_FROM_SRC.load()
                pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
                pdb.STREAM_SECT_HDR_ORIG.load()

            except AttributeError as e:
                pass
            # except Exception as e:
            #    print ("WARN: error %s parsing %s, skipping" % (e,pdbbase))
            #    not_found.append( (base, pdbbase) )
            #    continue

            try:
                sects = pdb.STREAM_SECT_HDR_ORIG.sections
                omap = pdb.STREAM_OMAP_FROM_SRC
            except AttributeError as e:
                # In this case there is no OMAP, so we use the given section
                # headers and use the identity function for omap.remap
                sects = pdb.STREAM_SECT_HDR.sections
                omap = DummyOmap()
            gsyms = pdb.STREAM_GSYM
            if not hasattr(gsyms, 'globals'):
                gsyms.globals = []

            last_sect = max(sects, key = attrgetter('VirtualAddress'))
            limit = base + last_sect.VirtualAddress + last_sect.Misc.VirtualSize

            self.addrs[base, limit] = {}
            self.addrs[base, limit]['name'] = pdbbase
            self.addrs[base, limit]['addrs'] = []
            for sym in gsyms.globals:
                if not hasattr(sym, 'offset'):
                    continue
                off = sym.offset
                try:
                    virt_base = sects[sym.segment - 1].VirtualAddress
                except IndexError:
                    continue

                mapped = omap.remap(off + virt_base) + base
                self.addrs[base, limit]['addrs'].append((mapped, sym.name))

            self.addrs[base, limit]['addrs'].sort(key = itemgetter(0))

        self.locs = {}
        self.names = {}
        for base, limit in self.addrs:
            mod = self.addrs[base, limit]['name']
            symbols = self.addrs[base, limit]['addrs']
            self.locs[base, limit] = [a[0] for a in symbols]
            self.names[base, limit] = [a[1] for a in symbols]

    def lookup(self, loc):
        if loc in self._cache:
            return self._cache[loc]

        for base, limit in self.addrs:
            if loc >= base and loc < limit:
                mod = self.addrs[base, limit]['name']
                symbols = self.addrs[base, limit]['addrs']
                locs = self.locs[base, limit]
                names = self.names[base, limit]
                idx = bisect_right(locs, loc) - 1
                diff = loc - locs[idx]
                if diff:
                    ret = "%s!%s+%#x" % (mod, names[idx], diff)
                else:
                    ret = "%s!%s" % (mod, names[idx])
                self._cache[loc] = ret
                return ret
        return "unknown"
