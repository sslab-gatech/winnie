#!/usr/bin/env python2
import argparse
import operator
import signal
from util import exit_gracefully

from logger import *
from harconf import *
from template import *

from common import SimpleTrace, Synthesizer

"""
./synthesizer.py harness -t temptrace/trace.log -d temptrace
./synthesizer.py harness -t temptrace/trace.log -d temptrace --start avformat_open_input
./synthesizer.py harness -t temptrace_gom/trace.log -d temptrace_gom -f temptrace_gom/functype --start avformat_open_input --sample-name small.mp4

./synthesizer.py diff --input-dummy temptrace_aimp/aimp_without_playlist.log --input-parse temptrace_aimp/aimp_with_playlist.log --output temptrace_aimp/trace.log
"""

logger = getlogger("Synthesizer")


class Differ:
    def __init__(self, in_dummy_pn, in_parse_pn, output_pn):
        self.in_dummy_pn = in_dummy_pn
        self.in_parse_pn = in_parse_pn
        self.output_pn = output_pn

        self.dummy_trace = SimpleTrace(self.in_dummy_pn)
        self.parse_trace = SimpleTrace(self.in_parse_pn)

        dummy_trace_sort = sorted(
            list(self.dummy_trace.unique_call.items()), key=operator.itemgetter(1))
        parse_trace_sort = sorted(
            list(self.parse_trace.unique_call.items()), key=operator.itemgetter(1))

        dummy_calls = []
        for k, v in dummy_trace_sort:
            dummy_calls.append(k)

        for k, v in parse_trace_sort:
            if k not in dummy_calls:
                print("CALLID[{0:05d}]: {1}".format(v, k))

        # print len(self.dummy_trace.unique_call)
        # print len(self.parse_trace.unique_call)


class SingleSynthesizer(Synthesizer):
    def build_body(self):
        # we should consider both call_tarce and ret_trace

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

            args = calltrace.args
            args_dump = calltrace.args_dump
            args_ptr = calltrace.pointer

            # one of core functions (we should do pointer analysis here)
            need_to_define, arguments = self.ret_arg_code(cid, args, args_dump, args_type, args_ptr)
            need_to_define_str = ' '.join(need_to_define).strip()
            self.history[cid] = (need_to_define, arguments)

            func_snippet = FUNC.replace("{funcname}", funcname)

            if need_to_define_str == '':
                func_snippet = func_snippet.replace("{print_cid}", "/* Harness function #%d */" % cid)
            else:
                func_snippet = func_snippet.replace("{print_cid}", "/* Harness function #%d */\n    %s" % (cid, ' '.join(need_to_define)))

            func_snippet = func_snippet.replace("{arguments}", ', '.join(arguments))

            if ret_type == '':
                func_snippet = func_snippet.replace("{ret_statement}", "")
                func_snippet = func_snippet.replace("{dbg_printf}",
                                                    'dbg_printf("%s\\n");' % (funcname))
            else:
                func_snippet = func_snippet.replace("{ret_statement}", "%s %s_ret = " % (ret_type, funcname))
                func_snippet = func_snippet.replace("{dbg_printf}",
                                                    'dbg_printf("%s, ret = %%d\\n", %s_ret);' % (funcname, funcname))

            self.body.append(func_snippet)


def main():
    # DEFINE PARSER
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(help="subparser")

    # subparser: harness generation
    har_parser = subparser.add_parser('harness')
    har_parser.add_argument("-t", "--trace", dest="trace_file", type=str,
                            default=None, help="Trace file collected from DynamoRIO",
                            required=False)
    har_parser.add_argument("-d", "--memory-dump", dest="dump_dir", type=str,
                            default=None, help="memory dump file directory (pre/post)",
                            required=False)
    har_parser.add_argument("-f", "--function-type", dest="functype", type=str,
                            default=None, help="function type information from IDA (and fixed pointer by trace)",
                            required=False)
    har_parser.add_argument("-s", "--start", dest="start_func", type=str,
                            default=None, help="name of the starting function to process",
                            required=False)
    har_parser.add_argument("-sample", "--sample-name", dest="sample_name", type=str,
                            default=None, help="name of the original sample name",
                            required=False)
    har_parser.set_defaults(action='harness')

    # subparser: diff trace
    diff_parser = subparser.add_parser('diff')
    diff_parser.add_argument('--input-dummy', dest="input_dummy", type=str)
    diff_parser.add_argument('--input-parse', dest="input_parse", type=str)
    diff_parser.add_argument('--output', dest="output", type=str)
    diff_parser.set_defaults(action='diff')

    args = parser.parse_args()
    # END PARSER

    # Ctrl-c handler
    signal.signal(signal.SIGINT, exit_gracefully(signal.getsignal(signal.SIGINT)))

    # Start harness synthesizer
    if args.action == 'harness':
        syn = SingleSynthesizer(args.trace_file, args.dump_dir,
                                args.functype, args.start_func, args.sample_name)
        syn.build_body()
        syn.emit_code()
        # syn.search_pointer(0x1f75ac0)
        # syn.search_pointer(0x65aa89a0)

    elif args.action == 'diff':
        diff = Differ(args.input_dummy, args.input_parse, args.output)


if __name__ == '__main__':
    main()
