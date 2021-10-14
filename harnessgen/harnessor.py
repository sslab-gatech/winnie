#!/usr/bin/env python3
import os
import glob

from harconf import *


class Tracer(object):
    def __init__(self, project):
        self.project = project
        self.dir = os.path.join(TRACE_PN, self.project)
        self.filelist = glob.glob(self.dir+"/*.log")
        self.normalfile = self.find_normal_file()  # store normal (no interesting points)
        self.filelist.remove(self.normalfile)

        self.trace_normal = None
        self.trace_interesting = {}
        self.trace_interesting_line = {}
        self.trace_interesting_line2index = {}
        self.list_diff = {}
        self.funcline_diff = {}
        self.modulename = None

    def find_normal_file(self):
        for filename in self.filelist:
            if "_"+NORMAL_POSTFIX in filename:
                return filename
        raise Exception("No normal file which contains _normal")

    @property
    def files(self):
        return self.filelist

    def collect_trace(self):
        self.unique_functions_normal, self.modulename, self.unique_functions_line, _ \
            = parse_trace_unique_callee(self.normalfile)

        for filename in self.filelist:
            #print (filename)
            basename = os.path.basename(filename)
            self.trace_interesting[basename], _, self.trace_interesting_line[basename], \
                self.trace_interesting_line2index[basename] = parse_trace_unique_callee(filename)

    def extract_unique_callsite(self):
        for filename in self.filelist:
            #print (list_diff(self.trace_interesting[os.path.basename(filename)], self.unique_functions_normal))
            basename = os.path.basename(filename)
            self.list_diff[basename] = list_diff(self.trace_interesting[basename], self.unique_functions_normal)
            self.funcline_diff[basename] = list_diff(self.trace_interesting_line[basename], self.unique_functions_line)

    def print_unique_trace(self):
        # print-out the first line of unique call (indirect/direct/ind-jmp)

        for key in self.list_diff.keys():
            print('\n' + key)
            for x in range(len(self.funcline_diff[key])):
                print(self.funcline_diff[key][x], self.trace_interesting_line2index[key][self.funcline_diff[key][x]])

    def extract_interesting_trace(self, outdir):

        for key in self.list_diff.keys():
            #print ('\n' + key)
            idx_list = []
            for x in range(len(self.funcline_diff[key])):
                idx = self.trace_interesting_line2index[key][self.funcline_diff[key][x]]
                idx_list.append(idx)

            min_val, max_val = extract_minmax(idx_list)
            out_pn = os.path.join(outdir, key)
            dump_extracted_trace(min_val, max_val, out_pn, self.project)


def extract_minmax(idx_list):
    min_val = min(idx_list)
    max_val = max(idx_list)

    while True:
        if max_val - min_val > TRACE_MAX:
            idx_list.remove(max_val)
            max_val = max(idx_list)
        else:
            break

    return min_val, max_val


def list_diff(li1, li2):
    return (list(set(li1) - set(li2)))


def get_module_name(chunk):
    lines = chunk.split("\n")
    if "T2M" in chunk:
        return lines[1].split(".dll")[0].split(" ")[-1]+".dll"

    elif "M2T" in chunk:
        return lines[0].split(".dll")[0].split(" ")[-1]+".dll"


def get_baseaddr(chunk, modulename):
    lines = chunk.split("\n")
    for line in lines:
        if modulename in line:
            return int(line.split(',')[2], 16)
    raise Exception("No modulename in the entry?")


def sanitize_fcall_line(line, baseaddr):
    addr = line.split("0x")[1].split(" ")[0]
    newaddr = hex(int(addr, 16) - baseaddr)[2:]

    if " @ " in line:
        line = line.split(" @ ")[1].strip()
    if "=> " in line:
        line = line.split("=> ")[1].strip()

    line = line.replace(" ? ??:0", "")
    line = line.replace(" ??:0", "")
    line = line.replace(" to ", "")
    line = line.replace(addr, newaddr)

    return line.strip()


def extract_call_addr(chunk, baseaddr):
    lines = chunk.split("\n")

    if lines[0].split(" ")[0].strip() in TRACE_PREFIX:
        if lines[0].split(" ")[1].strip() == "T2M":
            return int(lines[1].split("0x")[1].split(" ")[0], 16) - baseaddr, sanitize_fcall_line(lines[1], baseaddr)
        elif lines[0].split(" ")[1].strip() == "M2T":
            return int(lines[0].split("0x")[1].split(" ")[0], 16) - baseaddr, sanitize_fcall_line(lines[0], baseaddr)

        #print (chunk)
        raise Exception("No keyword? T2M or M2T?")
    else:
        return None, None


def dump_extracted_trace(min_val, max_val, out_pn, project):
    trace_pn = os.path.join(TRACE_PN, project, os.path.basename(out_pn))
    #print (trace_pn, filename)
    fdata = None
    out = ""

    with open(trace_pn, 'r') as f:
        fdata = f.read().split("==\n")

    modulename = get_module_name(fdata[1])
    baseaddr = get_baseaddr(fdata[-1], modulename)

    for x in range(min_val, max_val+1):
        chunk = fdata[x+1]
        out += chunk + "==\n"
    out += modulename + "|" + hex(baseaddr)

    with open(out_pn, 'w') as f:
        f.write(out)


def parse_trace_unique_callee(filename):
    unique_targets = []
    unique_funcline = []
    line2index = {}
    fdata = None

    with open(filename, 'r') as f:
        fdata = f.read().split("==\n")

    modulename = get_module_name(fdata[1])
    baseaddr = get_baseaddr(fdata[-1], modulename)

    for x in range(len(fdata)-1):
        chunk = fdata[x+1]
        fcall_addr, relavant_line = extract_call_addr(chunk, baseaddr)
        if fcall_addr is not None:
            line2index[relavant_line.strip()] = x
            if fcall_addr not in unique_targets:
                unique_targets.append(fcall_addr)
                unique_funcline.append(relavant_line)

                """
                if x not in line2index.keys():
                    line2index[relavant_line.strip()] = x
                """

    return unique_targets, modulename, unique_funcline, line2index


def main():
    tr = Tracer("notepad++")
    #tr = Tracer("aimp")
    tr.collect_trace()
    tr.extract_unique_callsite()
    # tr.print_unique_trace()
    tr.extract_interesting_trace("trace/extracted")


if __name__ == '__main__':
    main()
