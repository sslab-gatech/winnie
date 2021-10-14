#!/usr/bin/env python2
import os
import glob
import argparse
import signal
import typing
from util import exit_gracefully
from logger import *
from harconf import *
from template import *

from common import Synthesizer

"""
./syn-multi.py harness -t temptrace_math
./syn-multi.py harness -t temptrace_math --start test
./syn-multi.py harness -t temptrace_math --start test --sample-name input
"""

"""
[TARCE_DIR]
   - cor1_1   : 1st trace using the 1st correct input
   - cor1_2   : 2nd trace using the 1st correct input
   - cor2_1   : 3rd trace using the 2nd correct input
   - functype : function type information from IDA ==> fixed with dynamic information
   - decompile: decompiled results where the library call started

[NOTE]
   - cor1_1 and cor1_2 is used to infer the const value of argument
   - cor1_1 and cor2_1 is used to infer the possible impact of file-related operation
"""

logger = getlogger("Synthesizer")


class Identifier:
    def __init__(self, traces: typing.Dict[str, Synthesizer]):
        self.cor_trace1 = traces["cor1"]
        self.cor_trace2 = traces["cor2"]
        self.diff_trace = traces["diff"]

        # comparison result using same input should have result
        self.comp_cor = self.compare_cortrace()

        # comparison result using different inputs may not have result (i.e., null dict)
        self.comp_diff = self.compare_difftrace()

        self.report = self.make_report(self.comp_cor, self.comp_diff)

    def make_report(self, cor_dict, diff_dict):
        # NOTE: assume that diff_dict may not have any result
        #  - also, assume that the number of CIDs are same

        out = {}
        for cid in cor_dict.keys():
            arg = cor_dict[cid]

            if cid in diff_dict:
                arg += "\n" + diff_dict[cid]

            out[cid] = arg

        return out

    def analyze_args(self, args1, args2, cor):
        # args e.g.,  [[(2291628, 'DP'), (11, 'D')], [(9376112, 'CP'), (2347535189, 'D')]]
        # args e.g.,  [[(210, 'D')]]

        # NOTE: we assume that the length of args are same

        out = ""

        if cor == True:
            tag = "    // [DIFF] (Multi-runs using same input)"
        else:
            tag = "    // [DIFF] (Result with different inputs)"

        for x in range(len(args1)):
            rst = ""

            # pointer
            if args1[x][0][1] == 'DP' or args1[x][0][1] == 'CP':
                if args1[x][1][0] == args2[x][1][0]:
                    rst = "SAME"
                else:
                    rst = "DIFFERENT"
                out += "\n    //   - Arg[%d]: %s (referenced value is %s) |" % (
                    x, NAMEDIC[args1[x][0][1]], rst)

            # data
            else:
                if args1[x][0][0] == args2[x][0][0]:
                    rst = "SAME"
                else:
                    rst = "DIFFERENT"
                out += "\n    //   - Arg[%d]: DATA (value is %s) |" % (x, rst)

        out = tag + out

        return out

    def compare_cortrace(self):
        # compare cor_trace1 and cor_trace2
        """ report
         - arg1: data_pointer (referenced value SAME/DIFF), arg2: data (SAME)
         - data_pointer / code_pointer / data, SAME or DIFF
        """

        result = {}

        for cid in self.cor_trace1.trace.cid_sequence:

            if cid in self.cor_trace1.trace.calltrace and \
                    cid in self.cor_trace2.trace.calltrace:

                calltrace1 = self.cor_trace1.trace.calltrace[cid]
                calltrace2 = self.cor_trace2.trace.calltrace[cid]

                rettrace1 = self.cor_trace1.trace.rettrace[cid]
                rettrace2 = self.cor_trace2.trace.rettrace[cid]

                funcname1 = calltrace1.dst_symbol
                funcname2 = calltrace2.dst_symbol

                analyzed_result = self.analyze_args(
                    calltrace1.args, calltrace2.args, cor=True)
                result[cid] = analyzed_result
                # print analyzed_result

            else:
                result[cid] = None

        return result

    def compare_difftrace(self):
        # compare cor_Trace1 and diff_trace

        # NOTE: we not only compare the argument if the length of cids are same
        #  - we don't provide alignment for this problem

        result = {}

        # check all function names for each sequence is same
        for cid in self.cor_trace1.trace.cid_sequence:
            if cid in self.cor_trace1.trace.calltrace and \
                    cid in self.diff_trace.trace.calltrace:

                calltrace1 = self.cor_trace1.trace.calltrace[cid]
                calltrace2 = self.diff_trace.trace.calltrace[cid]
                funcname1 = calltrace1.dst_symbol
                funcname2 = calltrace2.dst_symbol

                if funcname1 != funcname2:
                    return result

        for cid in self.cor_trace1.trace.cid_sequence:

            if cid in self.cor_trace1.trace.calltrace and \
                    cid in self.diff_trace.trace.calltrace:

                calltrace1 = self.cor_trace1.trace.calltrace[cid]
                calltrace2 = self.diff_trace.trace.calltrace[cid]

                rettrace1 = self.cor_trace1.trace.rettrace[cid]
                rettrace2 = self.diff_trace.trace.rettrace[cid]

                funcname1 = calltrace1.dst_symbol
                funcname2 = calltrace2.dst_symbol

                analyzed_result = self.analyze_args(
                    calltrace1.args, calltrace2.args, cor=False)
                result[cid] = analyzed_result
                # print analyzed_result

            else:
                result[cid] = None

        return result


class MultiSynthesizer(Synthesizer):
    # one of the core logics for discovering pointer relationship
    def build_body(self, report):
        # we should consider both call_tarce and ret_trace
        #  - report: dictionary from the diff analysis

        pending_flag = True
        pending_count = 0
        prev_src_addr = 0
        prev_dst_addr = 0

        # 1) we need to handle used argument (raw value and pointer, ret-chain)
        for cid in self.trace.cid_sequence:
            variables = []  # defined variables: e.g., int a=0
            arguments = []  # used arguments: func(&a)
            calltrace = self.trace.calltrace[cid]
            rettrace = self.trace.rettrace[cid]
            funcname = calltrace.dst_symbol.decode()
            fi = self.trace.find_function(calltrace.dst_addr)
            ret_type = fi.ret_type
            args_type = fi.args

            msg = ""
            args = calltrace.args
            args_dump = calltrace.args_dump
            args_ptr = calltrace.pointer
            dst_addr = calltrace.dst_addr
            src_addr = calltrace.src_addr

            if src_addr == prev_src_addr and dst_addr == prev_dst_addr:
                pending_count = pending_count + 1
                pending_flag = True
            else:
                pending_count = 0
                pending_flag = False

            # one of core functions (we should do pointer analysis here)
            need_to_define, arguments = self.ret_arg_code(
                cid, args, args_dump, args_type, args_ptr)
            input_digging_result = self.dig_userinput(
                cid, args, args_dump, args_ptr)
            need_to_define_str = ' '.join(need_to_define).strip()
            self.history[cid] = (need_to_define, arguments)

            # build function snippet
            # print funcname, arguments
            if funcname not in self.defined_func:
                self.defined_func.append(funcname)
                func_snippet = FUNC.replace("{funcname}", funcname)
            else:
                func_snippet = FUNC_WO.replace("{funcname}", funcname)

            if need_to_define_str == '':
                func_snippet = func_snippet.replace(
                    "{print_cid}", "// Harness function #%d " % cid)
            else:
                func_snippet = func_snippet.replace(
                    "{print_cid}", "// Harness function #%d \n    %s" % (cid, ' '.join(need_to_define)))

            func_snippet = func_snippet.replace(
                "{arguments}", ', '.join(arguments))

            if ret_type == '':
                func_snippet = func_snippet.replace("{ret_statement}", "")
                func_snippet = func_snippet.replace("{dbg_printf}",
                                                    'dbg_printf("%s\\n");' % (funcname))
            else:
                func_snippet = func_snippet.replace(
                    "{ret_statement}", "%s %s_ret_%d = " % (ret_type, funcname, cid))
                func_snippet = func_snippet.replace("{dbg_printf}",
                                                    'dbg_printf("%s, ret = %%d\\n", %s_ret_%d);' % (funcname, funcname, cid))

            msg += "\n%s" % report[cid]

            # print "dist:", prev_src_addr, hex(abs (prev_src_addr - src_addr))
            if prev_src_addr != 0 and abs(prev_src_addr - src_addr) > THRESHOLD:
                msg += "\n    // Distance between prev/current libcall:%s, we recomment you to check the condition between them " % (
                    hex(abs(prev_src_addr - src_addr)))

            if pending_count > 0:
                msg += "\n    // [LOOP] This is %dth execution of %s() " % (
                    pending_count+1, funcname)
                self.body.append(msg+func_snippet)
            else:
                self.body.append(msg+func_snippet)

            prev_src_addr = src_addr
            prev_dst_addr = dst_addr


def main():
    # DEFINE PARSER
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(help="subparser")

    # subparser: harness generation
    har_parser = subparser.add_parser('harness')
    har_parser.add_argument("-t", "--trace", dest="trace_dir", type=str,
                            default=None, help="Trace dir collected from DynamoRIO",
                            required=False)
    har_parser.add_argument("-s", "--start", dest="start_func", type=str,
                            default=None, help="name of the starting function to process",
                            required=False)
    har_parser.add_argument("-sample", "--sample-name", dest="sample_name", type=str,
                            default=None, help="name of the original sample name",
                            required=False)
    har_parser.set_defaults(action='harness')

    args = parser.parse_args()
    # END PARSER

    # Ctrl-c handler
    signal.signal(signal.SIGINT, exit_gracefully(
        signal.getsignal(signal.SIGINT)))

    # Start harness synthesizer
    if args.action == 'harness':
        cor_trace_1 = glob.glob(os.path.join(
            args.trace_dir, MAIN_TRACE) + "/*.log")[0]
        cor_trace_2 = glob.glob(os.path.join(
            args.trace_dir, SECOND_TRACE) + "/*.log")[0]
        diff_trace = glob.glob(os.path.join(
            args.trace_dir, DIFF_TRACE) + "/*.log")[0]

        dumpdir = os.path.join(args.trace_dir, MAIN_TRACE, "memdump")
        dumpdir2 = os.path.join(args.trace_dir, SECOND_TRACE, "memdump")
        dumpdir_diff = os.path.join(args.trace_dir, DIFF_TRACE, "memdump")
        functype_pn = os.path.join(args.trace_dir, "functype_")

        syn_cor1 = MultiSynthesizer(cor_trace_1, dumpdir,
                               functype_pn, args.start_func, args.sample_name)
        syn_cor2 = MultiSynthesizer(cor_trace_2, dumpdir2,
                               functype_pn, args.start_func, args.sample_name)
        syn_diff = MultiSynthesizer(diff_trace, dumpdir_diff,
                               functype_pn, args.start_func, args.sample_name)

        traces = {}
        traces["cor1"] = syn_cor1
        traces["cor2"] = syn_cor2
        traces["diff"] = syn_diff

        identifier = Identifier(traces)
        report = identifier.report

        syn_cor1.build_body(report)
        syn_cor1.emit_code()
        # syn.search_pointer(0x1f75ac0)
        # syn.search_pointer(0x65aa89a0)


if __name__ == '__main__':
    main()
