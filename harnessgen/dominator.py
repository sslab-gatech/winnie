# For section IV-B: call-sequence recovery
# From specified targets (leaf nodes; e.g. CreateFile, ReadFile),
# This tries to find a dominator node (or LCA) that will call all of these targets

#!/usr/bin/env python2
import re
import typing
from common import Trace, TraceElement
import os
import signal
import argparse
import networkx as nx
import matplotlib.pyplot as plt

from tqdm import tqdm
from logger import *
from harconf import *
from template import *
from util import exit_gracefully

"""
./dominator.py -t domitrace_alzipcon/trace.log -d domitrace_alzipcon
./dominator.py -t domitrace_alzipcon/trace.log -d domitrace_alzipcon --start Format_QueryCollectionInfo
./dominator.py -t domitrace_alzipcon/trace.log -d domitrace_alzipcon --start Format_QueryCollectionInfo --end Format_Release --sample-name test.egg

alzip: answer is 0x4343d0 (4408272)
"""

logger = getlogger("Dominator")
DUMPDIR = ""
MERGE_BOUNDARY = True


class Dominator(object):
    def __init__(self, trace_pn, dump_pn, start_func=None, end_func=None, sample_name=None):
        self.dump_pn = dump_pn
        self.trace_pn = trace_pn
        self.start_func = start_func.encode()
        self.end_func = end_func.encode()
        self.sample_name = sample_name.encode()

        """
        self.trace_tid   = -1
        self.trace_tid2  = -1

        if self.start_func != None:
            self.start_cid, self.trace_tid = self.ret_start_point(self.trace_pn, self.start_func)
        if self.end_func != None:
            self.end_cid, self.trace_tid2 = self.ret_end_point(self.trace_pn, self.end_func)
        assert(self.trace_tid == self.trace_tid2)
        """

        self.start_cid, self.end_cid, self.interesting_tid, _ = self.ret_interesting_locations()
        self.trace = DominatorTrace(self.trace_pn, self.start_cid,
                                    self.end_cid, self.interesting_tid)

        self.defined_variables = []
        self.defined_pointer = {}   # {address:variable_name}
        self.body = []
        self.history = {}
        self.har_addr = {}

        """ ALL functions which used in the harness """
        for addr in list(self.trace.all_callers.keys()):
            # print hex(addr), self.trace.all_callers[addr]
            self.har_addr[addr] = self.trace.all_callers[addr]

        self.dominator()
        # print self.trace.callgraph.edges
        # print self.trace.func_boundary

    def dominator(self):

        # Calculate dominator using DFS and common address (Lowest common ancestor)
        unique_code_size = len(self.trace.node_list)
        all_nodes = self.trace.callgraph.nodes

        print("[*] Processing Directed-graph to find dominator")
        storage = []
        for harness_addr in tqdm(list(self.trace.all_callers)):
            harness_addr_start = self.trace.get_func_start(harness_addr, merge_boundary=MERGE_BOUNDARY)
            out = []

            for i in range(unique_code_size - 1, 0, -1):
                # print(harness_addr, self.trace.node_list[i])
                if self.trace.node_list[i] == harness_addr_start or self.trace.node_list[i] == 0:
                    continue
                if self.trace.node_list[i] not in all_nodes:
                    continue

                # print harness_addr_start, self.trace.node_list[i]
                for path in nx.all_simple_paths(self.trace.callgraph, source=self.trace.node_list[i], target=harness_addr_start, cutoff=50):
                    out = out + path

            out = list(dict.fromkeys(out))
            # print out
            storage = storage + out

        # Print out the report
        print("[*] Displaying Most Frequent Address (Dominator candidates)")
        func_counter: typing.Dict[int, int] = {}
        for func_addr in storage:
            func_counter[func_addr] = func_counter.get(func_addr, 0) + 1

        popular_words = sorted(func_counter, key=func_counter.get, reverse=True)
        most_func_count = func_counter[popular_words[0]]

        report_addr = []
        for addr in func_counter.keys():
            if func_counter[addr] == most_func_count:
                report_addr.append(addr)

        print(" >> Total unique harness functions: %d" % (len(self.trace.all_callers)))
        print(" >> Total number of function address identified: %d" % most_func_count)
        print(" >> Total number of candidate address(es): %d" % len(report_addr))
        # print(" >> Total number of candidate address(es): %d" % ', '.join(report_addr))

        # for debug
        # report_addr = ['0x421000', '0x430200', '0x4333c0', '0x424410', '0x41a590', '0x424e20', '0x44d0b0', '0x4477d0', '0x421440', '0x424230', '0x4335c0', '0x433de0', '0x424a10', '0x430e40', '0x452a60', '0x4243f0', '0x44b8c0', '0x447850', '0x4331a0', '0x40fdd0', '0x436860', '0x430610', '0x41ac80', '0x433340', '0x452e70', '0x4339c0', '0x430880', '0x4242c0', '0x4343d0', '0x44ccf0', '0x40fc90', '0x44d200', '0x44baa0', '0x42eea0', '0x41a570', '0x4346b0', '0x4160c0', '0x432920', '0x4330d0', '0x4260d1', '0x423d90', '0x420ac0', '0x424ac0', '0x4308e0', '0x4179d0', '0x423f90', '0x4483a0', '0x424cf0', '0x423360', '0x42e720', '0x457500', '0x447480', '0x417f80', '0x422000', '0x422920', '0x430710', '0x41a610', '0x44d2c0', '0x44d920', '0x433530', '0x422c20', '0x424890', '0x420f30', '0x430680', '0x421ee0', '0x452b10', '0x41ed40', '0x448ae0', '0x421370', '0x424330', '0x447120', '0x430260', '0x44d6b0', '0x430d60', '0x422c90', '0x424c80', '0x422d00', '0x42eb70', '0x422e00', '0x408e80', '0x4326e0', '0x40e180', '0x447940', '0x430f80', '0x422b90', '0x4329e0', '0x44bf90', '0x446fa0', '0x424af0', '0x406ce0', '0x423910', '0x44d9b0', '0x433b10', '0x434330', '0x4231c0', '0x4211a0', '0x433800', '0x44c020', '0x41f0e0', '0x44dbd0', '0x4129c0', '0x44be10', '0x420a40', '0x44e2a0', '0x430de0', '0x418050', '0x434600', '0x415df0', '0x424e40']

        # Heuristics
        """
        1. display report address with CID (CALLID)
        2. display observed number of that address in the trace
           (less number is desirable, should be 1?)
        3. display upper address of that function
        """

        print("\n[*] Dominator analysis")
        candidate = {}
        candidate["good"] = []
        candidate["bad"] = []
        for addr in report_addr:
            count = self.ret_addr_count_trace(addr)  # how many times called?

            if count == 1:
                candidate["good"].append(addr)
            else:
                candidate["bad"].append(addr)

        final_report = {}
        for good_addr in candidate["good"]:
            final_report[good_addr] = self.distance_from_startcid(good_addr)

        final_report = sorted(final_report, key=final_report.get, reverse=False)

        print(" >> Bad candidate (called multiple times): %s" % ', '.join(hex(addr) for addr in candidate["bad"]))
        print(" >> Good candidate (called only once): %s" % ', '.join(hex(addr) for addr in candidate["good"]))
        print(" >> Candidate address (sorted by the distance from harness): %s" % ', '.join(hex(addr) for addr in final_report))

        """ how to find this address?
        [*] Dominator analysis
        {'0x40fc90': 3618, '0x44b8c0': 3493, '0x41a610': 3737, '0x447940': 3242, '0x4335c0': 3615, '0x42eea0': 3504, '0x447120': 3616, '0x446fa0': 3606, '0x452e70': 3601, '0x40e180': 3746, '0x432920': 3604, '0x4346b0': 3168}
         >> Candidate address (sorted by the distance from harness):
        ['0x4346b0', '0x447940', '0x44b8c0', '0x42eea0', '0x452e70', '0x432920', '0x446fa0', '0x4335c0', '0x447120', '0x40fc90', '0x41a610', '0x40e180']

                  (answer)
        4346b0 <- 41a610 <- 40e180
        41a610 <- 40fc90
        """

    def distance_from_startcid(self, good_addr):
        current_cid = 0
        for cid in list(self.trace.calltrace.keys()):
            if good_addr == self.trace.calltrace[cid].dst_addr:
                current_cid = cid
        return self.start_cid - current_cid

    def ret_addr_count_trace(self, dst_addr):
        counter = 0
        for cid in list(self.trace.calltrace.keys()):
            if dst_addr == self.trace.calltrace[cid].dst_addr:
                if self.start_cid > cid:
                    counter += 1
                else:
                    counter += 2
        return counter

    def ret_interesting_locations(self):
        start_cid = None
        start_tid = None
        end_cid = 9e999
        end_tid = -1

        node_out = []

        with open(self.trace_pn, 'rb') as f:
            lines = f.readlines()
            for line in lines:

                if b" DC " in line or b" IC " in line or b" IJ " in line or b" FR " in line:
                    src_addr = int(line.split(b"->")[0].split(b"(")[0].split(b"0x")[1], 16)
                    # dst_addr = int(line.split(b"->")[1].split(b"(")[0], 16)
                    if src_addr not in node_out:
                        node_out.append(src_addr)

                if self.start_func in line and b"0x0" in line:
                    cid = int(line.split(b"CALLID[")[1].split(b"]")[0])
                    tid = int(line.split(b"TID[")[1].split(b"]")[0])

                    if start_cid == None:
                        start_cid = cid
                        start_tid = tid

                if self.end_func in line and b"0x0" in line:
                    cid = int(line.split(b"CALLID[")[1].split(b"]")[0])
                    tid = int(line.split(b"TID[")[1].split(b"]")[0])

                    end_cid = cid
                    end_tid = tid

        return start_cid, end_cid, start_tid, node_out


class DominatorTrace(Trace):
    # TODO: parse all traces, now we are tracing specified threadID with starting point
    def __init__(self, trace_pn, start_cid, end_cid, interesting_tid):
        super().__init__(trace_pn, DUMPDIR, interesting_tid, start_cid, build=False)
        self.func_boundary = {}
        self.src_to_dst = {}
        self.dst_from_src = {}
        self.start_cid = start_cid
        self.end_cid = end_cid
        self.all_callers = {}
        self.node_list = []
        self.callgraph = nx.DiGraph()

        self.possible_return = {}
        self.build()

        # test
        # print(self.calltrace[0])
        # print(self.rettrace[1])

        self.func_boundary = self.sanitize_func_boundary()  # dict{start:dst}
        self.generate_digraph()  # store to self.callgraph
        # self.show_graph()

        # print self.func_boundary

        """ TEST function boundary (start ==> dst)
        for key in self.func_boundary.keys():
            print(hex(key), hex(self.func_boundary[key]))  # src->dst
        """

        """ TEST whether same source has multiple targets (i.e., indirect call)
        for key in self.src_to_dst.keys():
            print(hex(key), self.src_to_dst[key])
        """

        """ TEST Xref functions (i.e., who are calling this function?)
        for key in self.dst_from_src.keys():
            print(hex(key), self.dst_from_src[key])
        """

    def generate_digraph(self):
        for cid in list(self.calltrace.keys()):
            te = self.calltrace[cid]

            start = te.src_addr
            end = te.dst_addr
            func_start = self.get_func_start(start, merge_boundary=MERGE_BOUNDARY)
            # if func_start == 0 and src_addr == 4303892:
            #    print "here", src_addr, dst_addr
            if func_start not in self.node_list:
                self.node_list.append(func_start)
                # print src_addr, func_start
            self.callgraph.add_edge(func_start, end)
            # print(f"Call {hex(start)}: {hex(func_start)} -> {hex(end)}")

    def show_graph(self):
        nx.draw(self.callgraph, node_size=200)
        plt.show()

    def get_func_start(self, addr, merge_boundary=False):
        # for start_addr in self.func_boundary.keys():
        #     if start_addr <= addr <= self.func_boundary[start_addr]:
        #         return start_addr

        # # one more try to find and change the function boundary
        # """
        #  Before>
        #  A ---- B       C-----D
        #             E
        #  After>
        #  A ---------E   C-----D

        #  option1: just return A
        #  option1: return A and modify the function boundary
        # """
        # if merge_boundary:
        #     # find cloest boundary
        #     diff = 0x100000
        #     candidate = 0
        #     for start_addr in self.func_boundary.keys():
        #         end_addr = self.func_boundary[start_addr]
        #         if end_addr < addr < end_addr + diff:
        #             candidate = start_addr
        #             diff = addr - end_addr

        #     if candidate != 0:
        #         return candidate

        # Addition: use function type database
        mod, mod_base, _ = self.find_module(addr)
        if mod:
            ft = self.functype_manager.get(mod)
            fi = ft.by_addr_near(addr - mod_base)
            return fi.addr + mod_base

        # finally we give up
        return 0

    def sanitize_func_boundary(self):
        out = {}

        for key in list(self.func_boundary.keys()):
            start_addr = key
            end_addr = self.func_boundary[key]

            # print start_addr, end_addr
            if end_addr == -1:
                continue

            if end_addr - start_addr > 0x10000:
                continue

            out[start_addr] = end_addr
        return out

    def insert_relationship(self, src, dst):

        if src not in list(self.src_to_dst.keys()):
            self.src_to_dst[src] = []
            self.src_to_dst[src].append(dst)
        else:
            if dst not in self.src_to_dst[src]:
                self.src_to_dst[src].append(dst)

        if dst not in list(self.dst_from_src.keys()):
            self.dst_from_src[dst] = []
            self.dst_from_src[dst].append(src)
        else:
            if src not in self.dst_from_src[dst]:
                self.dst_from_src[dst].append(src)

    def windows_target(self, te: TraceElement):
        dlls = [b"kernelbase.dll", b"kernel32.dll", b"ntdll.dll"]

        if te.dst_module and te.dst_module not in dlls:
            return False

        return True

    def parse_call(self, chunk: bytes, tid, cid):
        te = super().parse_call(chunk, tid, cid)
        src_addr = te.src_addr
        dst_addr = te.dst_addr

        # for finding fucntion boundary
        self.possible_return[src_addr] = dst_addr

        if dst_addr not in self.func_boundary:
            self.func_boundary[dst_addr] = -1

        # for making src_to_dst and dst_from_src relationship
        self.insert_relationship(src_addr, dst_addr)

        if cid >= self.start_cid and cid <= self.end_cid:
            if te.has_symbols and src_addr not in self.all_callers and not self.windows_target(te):
                self.all_callers[src_addr] = te.src_symbol

        return te

    def parse_ret(self, chunk: bytes):
        te = super().parse_ret(chunk)

        # update for building function boundary
        self.update_ret_addr(te.dst_addr, te.src_addr)

        return te

    # dst_addr is returning address (returining target)
    def update_ret_addr(self, dst_addr, current_addr):
        for addr in self.possible_return.keys():
            # found return place
            if addr <= dst_addr <= addr + 7:
                start_addr = self.possible_return[addr]
                self.func_boundary[start_addr] = max(
                    self.func_boundary[start_addr], current_addr)


def main():
    global DUMPDIR
    # DEFINE PARSER
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--trace", dest="trace_file", type=str,
                        default=None, help="Trace file collected from DynamoRIO",
                        required=True)
    parser.add_argument("-d", "--memory-dump", dest="dump_dir", type=str,
                        default=None, help="memory dump file directory (pre/post)",
                        required=True)
    parser.add_argument("-s", "--start", dest="start_func", type=str,
                        default=None, help="name of the starting function to process",
                        required=False)
    parser.add_argument("-e", "--end", dest="end_func", type=str,
                        default=None, help="name of the ending function to process",
                        required=False)
    parser.add_argument("-sample", "--sample-name", dest="sample_name", type=str,
                        default=None, help="name of the original sample name",
                        required=False)
    args = parser.parse_args()
    # END PARSER

    # Ctrl-c handler
    signal.signal(signal.SIGINT, exit_gracefully(
        signal.getsignal(signal.SIGINT)))

    # Start harness dominator
    DUMPDIR = args.dump_dir
    domi = Dominator(args.trace_file, args.dump_dir,
                     args.start_func, args.end_func, args.sample_name)


if __name__ == '__main__':
    main()
