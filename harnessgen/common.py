import subprocess
import typing
import re
import json
import hashlib
import os
import bisect
from harconf import *
from template import *
from util import strings, u32

### PARSER: COMMON


def get_baseaddr(chunk: bytes, modulename: bytes):
    lines = chunk.split(b"\n")
    for line in lines:
        if modulename in line:
            return int(line.split(b',')[2], 16)
    raise Exception("No modulename in the entry?")


def ret_start_point(pn: str, keyword: bytes):
    """
    1) return cid and tid from this example line
    CALLID[3] TID[3756] IJ T2M 0x63621040->0x65cf6450(avformat-gp-57.dll!avformat_open_input+0x0)
    2) for now, this function is case sensitive
    """
    with open(pn, 'rb') as f:
        lines = f.readlines()
        for line in lines:
            if keyword in line and b"0x0" in line:
                cid = int(line.split(b"CALLID[")[1].split(b"]")[0])
                tid = int(line.split(b"TID[")[1].split(b"]")[0])
                return cid, tid

        raise Exception("Cannot find the starting function from the trace file")


### PARSER: FUNCTION

class Args:
    def __init__(self, name: bytes, addr: int, ret_type: str, args: typing.List[str], convention: str):
        """        
        e.g., ret : void
        e.g., args: ["int", "*int", int]
        """
        self.name = name
        self.addr = addr
        self.ret_type = ret_type
        self.args = args
        self.convention = convention  # std or cdecl

    def arg(self, index):
        if index < len(self.args):
            return self.args[index].replace("*", "")
        raise Exception("Index out of bound")

    def argtype(self, index):
        if index < len(self.args):
            arg = self.args[index]
            if "*" in arg:
                return "data"
            else:
                return "pointer"
        raise Exception("Index out of bound")

    @property
    def argsize(self):
        return len(self.args)

    @property
    def rettype(self):
        return self.ret_type


class Functype:
    def __init__(self, functype_pn):
        self.functypes_by_name = {}
        self.functypes_by_addr = {}
        self.functype_pn = functype_pn
        self.sorted_addr = []
        self.parse()

    def parse(self):
        with open(self.functype_pn, 'rb') as f:
            lines = f.readlines()
            for line in lines:
                if b"|" not in line:
                    continue

                payload = [x.strip() for x in line.strip().split(b"|", 2)]
                if payload[2] == "None":
                    continue

                # e.g., 0x000|aix_read_header|int __cdecl(int)|{"args": [...], "cc": "__stdcall", "ret_type": "..."}
                addr = int(payload[0], 16)
                funcname = payload[1]
                funcinfo = json.loads(payload[2])
                ret_type = funcinfo['ret_type']
                convention = funcinfo['cc']
                args = [arg['type'] for arg in funcinfo['args']]

                self.functypes_by_addr[addr] = \
                    self.functypes_by_name[funcname] = \
                    Args(funcname, addr, ret_type, args, convention)
                self.sorted_addr.append(addr)

        self.sorted_addr = sorted(self.sorted_addr)

    def by_name(self, funcname) -> Args:
        return self.functypes_by_name[funcname]

    def by_addr(self, funcaddr) -> Args:
        fi = self.functypes_by_addr.get(funcaddr)
        if not fi:
            return Args(b'', funcaddr, 'int', ['int'] * 9, '__cdecl')
        else:
            return fi

    def by_addr_near(self, funcaddr) -> Args:
        index = bisect.bisect_right(self.sorted_addr, funcaddr) - 1
        assert index != -1, "Function not found at %s!" % hex(funcaddr)
        addr = self.sorted_addr[index]
        return self.functypes_by_addr[addr]

### PARSER: TRACE


class TraceElement:
    # An argument looks like this: [(0x14334333, "DP"), (0x000000, "D")]
    args: typing.List[typing.List[typing.Tuple[int, str]]]

    # get dump from bin files
    args_dump: typing.List[typing.Tuple[bytes, bytes]]

    def __init__(self, tracetype: str, src_addr: int, dst_addr: int, src_module: bytes, dst_module: bytes):
        self.tracetype = tracetype  # either "call" or "ret"
        self.src_addr = src_addr
        self.dst_addr = dst_addr  # this is also return_address
        self.args = []
        self.args_dump = []
        self.ret_val = None

        # Optional symbols
        self.has_symbols = bool(dst_module or src_module)
        self.src_module = (src_module or '').lower()
        self.dst_module = (dst_module or '').lower()
        self.src_symbol = None
        self.dst_symbol = None

    def update_calltrace(self, dst_sym, args, args_dump, pointer):
        self.dst_symbol = dst_sym
        self.args = args
        self.args_dump = args_dump
        self.pointer = pointer

    def update_rettrace(self, ret_val):
        self.ret_val = ret_val

    def __repr__(self):
        return "TraceElement(%r, %s, %s)" % ((self.tracetype, hex(self.src_addr), hex(self.dst_addr)))


class FunctypeManager:
    cache = {}

    def __init__(self):
        pass

    @staticmethod
    def get(path) -> Functype:
        res = FunctypeManager.cache.get(path)
        if res:
            return res

        cache_out = FunctypeManager.dest_filename(path)
        cache_idb = cache_out + '.idb'
        command = [IDA_PATH, '-A', '-S' + IDA_SCRIPT]
        command += ['-o' + cache_idb, path] if not os.path.isfile(cache_idb) else [cache_idb]

        if not os.path.isfile(cache_out):
            print(f"Generating function types for {path.decode()} ...")
            subprocess.run(command,
                           env={'TVHEADLESS': '1', 'DESTPATH': cache_out, **os.environ})
        else:
            print(f"Found cached function types for {path.decode()} !")

        if not os.path.isfile(cache_out):
            raise Exception(f"Generating function type for {path} failed!\nCommand: {command}")

        res = FunctypeManager.cache[path] = Functype(cache_out)
        return res

    @staticmethod
    def dest_filename(path) -> str:
        return os.path.join(FUNCTYPE_CACHE_PATH, hashlib.sha256(path.lower()).hexdigest())


class Trace:
    # from print_address; address, [module, symbol, offset]. []: optional
    CALL_ENTRY = r'({address})(?:\(({module})!({symbol})\+({address})\))?'\
        .format(address=r'0x[0-9a-fA-F]+', module=r'[^!]*', symbol=r'[^+]*')\
        .encode()

    cid_sequence: typing.List[int]

    # TODO: parse all traces, now we are tracing specified threadID with starting point
    def __init__(self, trace_pn: str, dumpdir: str, tid=None, start_cid=None, build=True):
        self.trace_pn = trace_pn
        self.functype_manager = FunctypeManager()
        self.tid = tid
        self.start_cid = start_cid
        self.cid_sequence = []
        self.dumpdir = dumpdir

        if build:
            self.build()

        #self.module_baseaddr = None
        #self.caller_baseasddr = None

        """
        print hex(self.calltrace[0].src_addr)
        print hex(self.calltrace[0].dst_addr)
        print self.calltrace[0].dst_symbol
        print self.calltrace[0].args
        """

    def build(self):
        """
        Analyze trace with function_type information (limit the number of arguments)
        """
        calltrace: typing.Dict[int, TraceElement]
        rettrace: typing.Dict[int, TraceElement]

        calltrace = {}
        rettrace = {}

        self.modules = modules = {}

        with open(self.trace_pn, 'rb') as f:
            entries = f.read().split(b"==\n")
            entries, module_trace = entries[:-1], entries[-1]

            for line in module_trace.strip().split(b'\n')[1:]:
                line = map(lambda x: x.strip(), line.split(b',', 9))
                idx1, idx2, base, end, entry, a, b, c, path = line
                modules[path.lower()] = int(base, 16), int(end, 16)

            for x in range(len(entries) - 1):
                chunk = entries[x + 1]
                tid, cid, tracetype = self.get_tid(chunk)

                if self.tid is not None and tid != self.tid:
                    continue

                if tracetype == "CALL":
                    calltrace[cid] = self.parse_call(chunk, tid, cid)
                    self.cid_sequence.append(cid)

                elif tracetype == "RET":
                    rettrace[cid] = self.parse_ret(chunk)

            # store (for just in case)
            first_call = calltrace[self.cid_sequence[0]]
            self.module_baseaddr = modules[first_call.dst_module][0]
            self.caller_baseaddr = modules[first_call.src_module][0]

            # remove if None
            calltrace = {k: v for k, v in calltrace.items() if v is not None}
            rettrace = {k: v for k, v in rettrace.items() if v is not None}

        self.calltrace, self.rettrace = calltrace, rettrace

    def parse_arg(self, line: bytes, index, tid, cid):
        """ example
        -A9: 0x002eeec8[DP] > 0x002eef08[DP] > 0x002eef1c[DP] > 0x002eef3c
        """
        out: typing.List[typing.Tuple[int, str]]
        chain: typing.List[bytes]

        out = []
        chain = line.split(b":")[1].split(b">")

        for value in chain:
            if b"[" in value:
                pointer_type = value.split(b"[")[1].split(b"]")[0].decode()
                actual_value = int(value.split(b"[")[0], 16)
            else:
                pointer_type = "D"
                actual_value = int(value.strip().split(b" ")[0], 16)
            out.append((actual_value, pointer_type))

        return out

    def find_module(self, address: int) -> typing.Tuple[typing.Union[bytes, None], int, int]:
        for path, (base, end) in self.modules.items():
            if base <= address <= end:
                return path, base, end

        return None, 0, 0

    def find_function(self, address: int) -> typing.Union[Args, None]:
        mod, mod_base, _ = self.find_module(address)
        if not mod:
            return None

        ft = self.functype_manager.get(mod)
        fi = ft.by_addr(address - mod_base)
        return fi

    def parse_call(self, chunk: bytes, tid, cid, parse_args=True) -> TraceElement:
        """ example
        CALLID[0] TID[3756] IJ T2M 0x63621000->0x65cad480(avformat-gp-57.dll!avformat_get_riff_audio_tags+0x0)
         -A0: 0x636350a5[DP] > 0xa382c4a3
         ...
         -A9: 0x002eeec8[DP] > 0x002eef08[DP] > 0x002eef1c[DP] > 0x002eef3c

        CALLID[0] TID[3664] IC T2M @0x008f10de(math3.exe!fuzz_me+0xde)->0x735a1100(MathLibrary.dll!test+0x0)
        """
        lines = chunk.split(b"\n")
        arg_lines = list(filter(lambda x: x.startswith(b' -A'), lines[1:]))

        args = []
        args_dump = []
        pointer = []

        src, dst = re.findall(Trace.CALL_ENTRY, lines[0])
        src_addr = int(src[0], 16)
        dst_addr = int(dst[0], 16)
        src_module = src[1]
        dst_module = dst[1]

        dst_sym = None
        numargs = len(arg_lines)

        mod, _, _ = self.find_module(src_addr)
        if mod:
            src_module = mod

        mod, _, _ = self.find_module(dst_addr)
        if mod:
            dst_module = mod

        fi = self.find_function(dst_addr)
        if fi:
            dst_sym = fi.name
            numargs = fi.argsize

        # XXX: Tracer decides the maximum argument size
        numargs = min(numargs, len(arg_lines))

        if parse_args:
            # parse from A1 to A9 (a0 is ret addr (stack))
            for x in range(numargs):
                current_arg = self.parse_arg(arg_lines[x], x, tid, cid)
                args.append(current_arg)

                # FIXME: what if we meet code pointer? should we dump code?
                # FIXME: we should consider multi-level, multi-element
                if current_arg[0][1] == "DP":
                    dumpread, same, dump_pointer = self.read_dump(x, tid, cid)
                    args_dump.append(dumpread)
                    pointer.append(dump_pointer)
                else:
                    args_dump.append(None)
                    pointer.append(None)

        te = TraceElement("call", src_addr, dst_addr, src_module, dst_module)
        te.update_calltrace(dst_sym, args, args_dump, pointer)

        return te

    def read_dump(self, index, tid, cid):
        # filename e.g., t788-c99-a8.post

        pre_pn = os.path.join(
            self.dumpdir, "t%d-c%d-a%d.pre" % (tid, cid, index))
        post_pn = os.path.join(
            self.dumpdir, "t%d-c%d-a%d.post" % (tid, cid, index))

        with open(pre_pn, 'rb') as f:
            pre = f.read(BINREAD)
            f.seek(BINREAD)
            pre_pointer = f.read(1000)

        if not os.path.isfile(post_pn):  # unmap?
            post_pn = pre_pn

        with open(post_pn, 'rb') as f:
            post = f.read(BINREAD)
            f.seek(BINREAD)
            post_pointer = f.read(1000)

        return (pre, post), pre == post, (pre_pointer, post_pointer)

    def parse_ret(self, chunk: bytes) -> TraceElement:
        """ example
        RETID[2] TID[3756] RET2T 0x65be6913(avformat-gp-57.dll!av_register_all+0xcb3)->0x63641000(MediaSource.ax!libssh2_session_abstract+0x4b50)
        RETVAL: 0x00000001
        """
        lines = chunk.split(b"\n")
        assert len(lines) >= 2

        keyword = lines[0].split(b' TID')[1].split(b' ')[1]
        assert keyword in (b'RET2M', b'RET2T', b'RETFR'), 'Unknown keyword: %r' % keyword

        src, dst = re.findall(Trace.CALL_ENTRY, lines[0])
        src_addr = int(src[0], 16)
        dst_addr = int(dst[0], 16)

        ret_val = int(chunk.split(b"RETVAL:")[1].split(b'\n')[0], 16)

        te = TraceElement("ret", src_addr, dst_addr, src[1], dst[1])
        te.update_rettrace(ret_val)

        return te

    def get_tid(self, chunk: bytes):
        tracetype = ""
        cid = -1
        tid = -1
        if b" DC " in chunk or b" IC " in chunk or b" IJ " in chunk or b" FR " in chunk:
            tracetype = "CALL"
            cid = int(chunk.split(b"[")[1].split(b"]")[0])
        elif b"RET" in chunk:
            tracetype = "RET"
            cid = int(chunk.split(b"[")[1].split(b"]")[0])
        if b" TID[" in chunk:
            tid = int(chunk.split(b" TID[")[1].split(b"]")[0])

        assert(tracetype != "")

        # no tid information from the chunk
        return tid, cid, tracetype


class SimpleTrace(Trace):
    def __init__(self, trace_pn):
        self.trace_pn = trace_pn
        self.cid_sequence = []
        self.unique_call = {}
        self.calltrace = self.build()

    def build(self):
        calltrace = {}

        with open(self.trace_pn, 'rb') as f:
            fdata = f.read().split(b"==\n")
            for x in range(len(fdata) - 1):
                chunk = fdata[x + 1]
                tid, cid, tracetype = self.get_tid(chunk)

                if tracetype == "CALL":
                    calltrace[cid] = self.parse_call(chunk, tid, cid, parse_args=False)
                    self.cid_sequence.append(cid)

            # remove if None
            calltrace = {k: v for k, v in calltrace.items() if v is not None}
        return calltrace


# This is the important part; program synthesizer
class Synthesizer:
    def __init__(self, trace_pn: str, dump_pn: str, functype_pn: str, start_func=None, sample_name: str = None):
        self.dump_pn = dump_pn
        self.trace_pn = trace_pn
        self.start_func = start_func
        self.functype_pn = functype_pn
        self.sample_name = sample_name

        if self.start_func != None:
            self.start_cid, self.trace_tid = ret_start_point(self.trace_pn, self.start_func.encode())
        else:
            self.start_cid, self.trace_tid = None, None

        self.functype_manager = FunctypeManager()
        self.trace = Trace(self.trace_pn, self.dump_pn, self.trace_tid, self.start_cid)
        self.defined_types, self.defined_funcs = self.typedef()

        self.defined_variables = []
        self.defined_pointer = {}   # {address:variable_name}
        self.body = []
        self.defined_func = []
        self.history = {}

    def emit_code(self, out_pn=None):
        header = HEADER.replace("{typedef}", '\n'.join(self.defined_types))
        fuzzme = FUZZME.replace("{funcdef}", '\n'.join(self.defined_funcs))
        fuzzme = fuzzme.replace("{harness}", '\n'.join(self.body))

        print(header)
        print(fuzzme)
        print(MAIN)

    def typedef(self):
        """
        1) for each trace, we identify unique function
        2) we prepare type information (ready to emit)
        3) emit to global typedef
         e.g., typedef int (__stdcall *avformat_get_riff_audio_tags_func_t)();
        4) emit to fuzzme()
         e.g., avformat_get_riff_audio_tags_func_t  avformat_get_riff_audio_tags_func;
        """
        defined_types = []
        defined_funcs = []

        for cid in self.trace.cid_sequence:
            te = self.trace.calltrace[cid]
            funcname = te.dst_symbol
            mod, mod_base, _ = self.trace.find_module(te.dst_addr)
            assert mod
            funcinfo = self.functype_manager.get(mod).by_addr(te.dst_addr - mod_base)
            args = funcinfo.args
            args_str = ', '.join(args) if len(args) > 0 else ''
            convention = funcinfo.convention
            ret_type = funcinfo.ret_type

            _types = self.ret_typedef_func(
                funcname, args_str, convention, ret_type)
            _funcs = self.ret_defined_func(funcname)
            if _types not in defined_types:
                defined_types.append(_types)
            if _funcs not in defined_funcs:
                defined_funcs.append(_funcs)

        """
        for x in range(len(defined_types)):
            print defined_types[x]

        for x in range(len(defined_types)):
            print defined_funcs[x]
        """

        return defined_types, defined_funcs

    def analyze(self):
        # 1) infer argument for filepath or input data

        # 2) diff pre and post function

        # 3) discover used pointer
        pass

    def dig_userinput(self, cid, args, args_dump, args_ptr):

        input_pn = os.path.join(os.path.dirname(self.functype_pn), INPUT1)

        if os.path.exists(input_pn):
            userinput = open(input_pn, 'rb').read()
        else:
            return None

        # for x in range(len(args)):
        #     if args[x][0][1] == 'DP':
        #         print userinput in args_dump[x][0]

    def build_body(self, *args):
        raise NotImplementedError()

    def search_pointer(self, addr, passed_cid=10000, internal_use=False):
        """
        utility function to pinpoint the location of address in memory dump
        """

        result = []

        # for each callid
        for cid in self.trace.cid_sequence:

            if cid > passed_cid:
                continue

            variables = []  # defined variables: e.g., int a=0
            arguments = []  # used arguments: func(&a)
            calltrace = self.trace.calltrace[cid]

            args = calltrace.args
            args_dump = calltrace.args_dump
            args_ptr = calltrace.pointer

            for x in range(len(args)):
                current_arg = args[x][0][0]
                if current_arg == addr:
                    if not internal_use:
                        print("[*] Passed argument at [cid:%d] [arg:%dth]" % (cid, x))
                    else:
                        result.append(("arg", cid, x))

            for x in range(len(args)):
                if args[x][0][1] == 'DP':
                    postdump = args_dump[x][1]
                    for y in range(0, len(postdump), 4):
                        if addr == u32(postdump[y:y + 4]):
                            if not internal_use:
                                print("[*] Memory dump at [cid:%d] [arg:%dth] [idx:%d]" % (cid, x, y))
                            else:
                                result.append(("dump", cid, x, y))

        if not internal_use:
            return None
        else:
            return result

    def ret_pointer_at_dump(self, cid, arg, idx):
        # e.g., *((int*)c3_a0[3]
        # FIXME: assuming integer type
        return "*((int*)c%d_a%d[%d])" % (cid, arg, idx)

    def ret_addr_of_var(self, orig_val):
        return "&(%s)" % orig_val

    def check_searched_result(self, _result, query):
        # query: either "arg" or "dump"
        # return oldest one
        # print _result, "|", query
        if _result is None:
            return None

        for result in _result:
            keyword = result[0]
            if keyword == query:
                return result

        return None

    def ret_arg_code(self, cid, args, args_dump, args_type, args_ptr):
        """
        - cid: call id
        - args: actual argument values
        - args_dump: followed result from pointer array[0]=pre, array[1]=post
        - args_type: inferred type for each argument
        """
        need_to_define = []
        arguments = []
        pointer_defined_flag = False

        # 1) will use raw value (basically)
        # 2) if pointer, we define variable and pass the address
        # 3) if pointer indicates 0, we allocate heap with 1000 size
        for x in range(len(args)):
            pointer_defined_flag = False
            # data pointer
            if args[x][0][1] == 'DP':
                # TODO: consider data-type when unpack

                # 1) infer filename argument (if the string contains filename information)
                first_string = next(strings(args_dump[x][0]))
                if self.sample_name.encode() in first_string:
                    arguments.append("filename")
                    continue
                else:
                    dumped = hex(u32(args_dump[x][0]))
                _type = args_type[x].replace("*", "")

                # 1-1) infer chuck of actual sample is used in the function
                # TODO

                # 2) we allocate heap if pointed value is 0
                if dumped == '0x0':
                    # we always allocate enough space for pointer to zero (could be initialization)
                    need_to_define.append("%s* c%d_a%d = (%s*) calloc (%d, sizeof(%s));" %
                                          (_type, cid, x, _type, BINREAD, _type))
                    arguments.append("&c%d_a%d" % (cid, x))

                # 3) Check pre-defined pointer
                #    If there is, we reuse the pointer
                else:
                    # print args[x][0][0]

                    # Is the address is already referenced from the previous pointer?
                    # print cid
                    # print args[x][0][0]
                    # print self.defined_pointer.keys()
                    if args[x][0][0] not in self.defined_pointer:
                        # print hex(args[x][0][0])
                        result = self.search_pointer(args[x][0][0], cid, internal_use=True)
                        result_arg = self.check_searched_result(result, "arg")
                        result_dump = self.check_searched_result(result, "dump")

                        # print result_arg
                        # print result_dump

                        # 3-1) searches for the address from the previous operation
                        #      if there exist address in the dump (e.g., assigned after function call),
                        #      we try to use that (only if the dump exist previously)
                        if result is not None and result_dump is not None:
                            _cid = result_dump[1]
                            _arg = result_dump[2]
                            _idx = result_dump[3]
                            ptrname = self.ret_pointer_at_dump(_cid, _arg, _idx)
                            self.defined_pointer[args[x][0][0]] = ptrname
                            need_to_define.append('')
                            arguments.append(ptrname)
                            continue

                        # 3-2) what if the address is used by another arguments?
                        elif False:
                            # elif result is not None and result_arg is not None:
                            # print result
                            self.defined_pointer[args[x][0]
                                                 [0]] = "&c%d_a%d" % (cid, x)
                            need_to_define.append(
                                "%s c%d_a%d = %s;" % (_type, cid, x, dumped))

                        # 3-3) if not, we define new one
                        else:
                            self.defined_pointer[args[x][0]
                                                 [0]] = "&c%d_a%d" % (cid, x)
                            need_to_define.append(
                                "%s c%d_a%d = %s;" % (_type, cid, x, dumped))
                            pointer_defined_flag = True

                    # if it is pre-defined, we do nothing
                    else:
                        need_to_define.append('')

                    # If we don't have choice, we define new pointer
                    arguments.append(self.defined_pointer[args[x][0][0]])

                # 4) Check whether referenced value (from pointer) is defined as another pointer
                #    e.g., arg1|A --> 0x1000, arg1|B --> A -> 0x1000
                #           ==> B = &A (not just raw value of A)
                if pointer_defined_flag == True:
                    # now, we are selecting the referenced value (this is also address)
                    __result = self.search_pointer(
                        args[x][1][0], cid, internal_use=True)
                    # print "pointer", __result
                    __result_arg = self.check_searched_result(__result, "arg")
                    # print __result_arg

                    if __result_arg is not None:

                        result_cid = __result_arg[1]
                        result_arg = __result_arg[2]

                        # history = {cid: (need_to_define, arguments)}
                        # print "DEBUG", result_cid, result_arg, self.history, self.history[result_cid][1]
                        previous_argument = self.history[result_cid][1][result_arg]
                        addr_previous_argument = self.ret_addr_of_var(
                            previous_argument)

                        # rollback
                        del self.defined_pointer[args[x][0][0]]
                        arguments = arguments[:-1]
                        need_to_define = need_to_define[:-1]

                        # append arguments
                        self.defined_pointer[args[x][1]
                                             [0]] = addr_previous_argument
                        arguments.append(addr_previous_argument)
                        need_to_define.append('')

            elif args[x][0][1] == 'CP':
                """ failed trial
                code_pointer = args[x][0][0]
                self.defined_pointer[args[x][0][0]] = "&c%d_a%d" % (cid, x)
                need_to_define.append("%s c%d_a%d = %s;" % (_type, cid, x, code_pointer))
                arguments.append(self.defined_pointer[args[x][0][0]])
                """

                # print self.trace.caller_baseasddr

                raw_value = args[x][0][0]
                _type = args_type[x].replace("*", "")

                append_str = " /* Possible code pointer offset: %s */" % hex(
                    int(raw_value) - self.trace.caller_baseaddr)
                # print append_str

                # we provide the information about the code pointer
                need_to_define.append("")
                arguments.append(hex(raw_value) + append_str)

            # raw data
            elif args[x][0][1] == 'D':
                # TODO: consider data-type when unpack
                raw_value = args[x][0][0]
                _type = args_type[x].replace("*", "")

                need_to_define.append("")
                arguments.append(hex(raw_value))

        return need_to_define, arguments

    def ret_typedef_func(self, funcname, args_str, convention, ret_type):
        # e.g., typedef int (__stdcall *avformat_get_riff_audio_tags_func_t)();
        return "typedef %s (%s *%s_func_t)(%s);" % (ret_type, convention, funcname.decode(), args_str)

    def ret_defined_func(self, funcname):
        return (b"    %s_func_t %s_func;" % (funcname, funcname)).decode()
