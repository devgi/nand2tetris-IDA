import struct

import idaapi


# http://www.hexblog.com/?p=110

# ROM max size is 32k
ROM_MAX_SIZE =  2 **15
INSTRUCTION_SIZE = 16


def accept_file(li, n):
    if n > 0:
        return 0

    size = li.size()

    # Verify that the file size is not too big or too small.
    if size > (ROM_MAX_SIZE * (INSTRUCTION_SIZE + 2)) or size < INSTRUCTION_SIZE:
        return 0

    li.seek(0)
    data = li.read(size)

    for line in data.splitlines():
        # Ignore empty lines.
        line = line.strip()
        if line:
            if len(line) != INSTRUCTION_SIZE:
                return 0

            if not set(line).issubset(set(['0', '1'])):
                return 0

    return "Nand2Tetris: Hack Assembly"

def load_file(li, neflags, format):
    idaapi.set_processor_type("n2t-hack", idaapi.SETPROC_ALL|idaapi.SETPROC_FATAL)

    li.seek(0)
    hack_data = li.read(li.size())

    hack_instructions = [int(instruction, 2) for instruction in hack_data.splitlines()]
    hack_instructions_bin = ''.join(struct.pack("!H", instruction) for instruction in hack_instructions)
    print "Found %d hack instructions" % len(hack_instructions)


    seg = idaapi.segment_t()
    seg.startEA= 0
    seg.endEA = len(hack_instructions)

    seg.align = idaapi.saAbs
    seg.comb = idaapi.scPriv
    seg.bitness = 0 # 16-bit

    idaapi.add_segm_ex(seg, "Hack-ROM", "CODE", idaapi.ADDSEG_OR_DIE)

    # This method seems to change in next versions.
    #idaapi.mem2base(hack_instructions_bin, 0, -1)
    idaapi.mem2base(hack_instructions_bin, 0)

    return 1