# Output basic block addresses for a binary in the format Winnie-AFL expects:
# [module_name.exe/.dll]
# relative virtual address,file offset
# ...
# [module #2]
# rva,file offset
# ...
#
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from ghidra.program.flatapi import FlatProgramAPI
from datetime import datetime
import os

def main():
    # File to write output to
    output_path = "{}/{}".format(os.getcwd(), datetime.now().strftime("bblist_{}_%d_%m_%y_%H_%M_%S.bb".format(currentProgram.getName())))
    output_file = open(output_path, "w")

    bbm = BasicBlockModel(currentProgram)
    blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)
    flat_api = FlatProgramAPI(currentProgram)

    # Write module name - for now, just the current program's executable module
    output_file.write("[{}]\n".format(currentProgram.getName()))

    # Add up size of sections preceding executable section to get file offsets
    # We assume that the sum of the sizes of each block before the executable
    # block is equal to the file offset of the executable block
    # (this script only works for the first executable section)
    sections = currentProgram.getMemory().getBlocks()
    precedingSectionSize = 0
    exeSectionStart = 0
    for s in sections:
        if s.isExecute():
            exeSectionStart = s.getStart().getOffset()
            break
        precedingSectionSize += s.getSize()
        print "Size of section {}:{}".format(s.getName(), s.getSize())

    blocks_skipped = 0
    while True:
        block = blocks.next()
        if not block:
            break
        # Skip BBs that already have breakpoints
        if flat_api.getByte(block.minAddress) == -52:
            blocks_skipped += 1
            continue
        rva = block.minAddress.subtract(currentProgram.getImageBase().getOffset()).getOffset()
        file_offset = block.minAddress.subtract(exeSectionStart - precedingSectionSize).getOffset()
        cur_line = "0x{:x},0x{:x}\n".format(rva, file_offset)
        output_file.write(cur_line)

    print "Skipped {} BBs that already had breakpoints".format(blocks_skipped)
    print "Output written to {}".format(output_path)

if __name__ == "__main__":
    main()

