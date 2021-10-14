from __future__ import print_function

import idaapi
import idautils
import ida_kernwin
import idc

import os

baseaddr = idaapi.get_imagebase()
dumped = set()
module_name = idaapi.get_root_filename()
SIZE_LIMIT = 0

def main():
    out_file_name = ida_kernwin.ask_file(True, 'basicblocks.bb', 'Select output file')

    print('Will save to %s' % out_file_name)

    if os.path.isfile(out_file_name):
        # validate existing file before appending to it
        with open(out_file_name, 'r') as f:
            for line in f:
                if line.startswith('[') and module_name in line:
                    warning('Module %s already exists in %s' % (module_name, os.path.basename(out_file_name)))
                    return

    with open (out_file_name, 'a') as f:
        f.write('[%s]\n' % (module_name,))
        for fva in idautils.Functions():
            dump_bbs(fva, f)
        f.close()

    print('OK, done. Found %d basic blocks' % (len(dumped),))
    ida_kernwin.info('Saved to %s' % (out_file_name,))

def dump_bbs(fva, outfile):
    func = idaapi.get_func(fva)
    cfg = idaapi.FlowChart(func)    
    for bb in cfg:
        if bb.start_ea not in dumped and bb.end_ea - bb.start_ea > SIZE_LIMIT:
            dumped.add(bb.start_ea)
            result = format_bb(bb) 
            # print (result)
            outfile.write(result + '\n')

def format_bb(bb):
    return ("0x%x,0x%x" % (bb.start_ea - baseaddr, idaapi.get_fileregion_offset(bb.start_ea))) 

if __name__ == "__main__":
    main()
