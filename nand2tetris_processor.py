import itertools

import idaapi
from idaapi import (processor_t, get_16bit, cvar,
                    PRN_BIN, CF_STOP, CF_CHG1, CF_CHG2, CF_CHG3, CF_USE1, CF_USE2,
                    ASD_DECF0, ASH_HEXF3, ASO_OCTF4, ASB_BINF3, AS_ASCIIC,
                    AS_ASCIIZ, o_void, o_reg, o_imm, dt_byte)

PREDEFINED_SYMBOLS = dict(
    SP=0,
    LCL=1,
    ARG=2,
    THIS=3,
    THAT=4,

    R5=5,
    R6=6,
    R7=7,
    R8=8,
    R9=9,
    R10=10,
    R11=11,
    R12=12,
    R13=13,
    R14=14,
    R15=15,

    SCREEN=0x4000,
    KBD=0x6000
)

REG_A = "A"
REG_D = "D"
REG_M = "M"

LEGAL_REGS = [REG_A, REG_D, REG_M]

# A instruction consts.
LOAD = "@"

# C instruction consts.
JMP_SEP = ';'
DST_SEP = "="

JUMP_null = "" # Null jump is empty and not "null"
JUMP_JGT = "JGT"
JUMP_JEQ="JEQ"
JUMP_JGE="JGE"
JUMP_JLT="JLT"
JUMP_JNE="JNE"
JUMP_JLE="JLE"
JUMP_JMP="JMP"

LEGAL_JUMP = (JUMP_null, JUMP_JGT , JUMP_JEQ, JUMP_JGE,
              JUMP_JLT, JUMP_JNE, JUMP_JLE, JUMP_JMP)

DEST_null="" # Null dest is empty and not "null"
DEST_M="M"
DEST_D="D"
DEST_MD="MD"
DEST_A="A"
DEST_AM="AM"
DEST_AD="AD"
DEST_AMD="AMD"

LEGAL_DEST =  (DEST_null, DEST_M, DEST_D, DEST_MD,
               DEST_A, DEST_AM, DEST_AD, DEST_AMD)

COMP_0="0"
COMP_1="1"
COMP_NEG_1="-1"
COMP_D="D"
COMP_A="A"
COMP_NOT_D="!D"
COMP_NOT_A="!A"
COMP_NEG_D="-D"
COMP_NEG_A="-A"
COMP_D_PLUS_1="D+1"
COMP_A_PLUS_1="A+1"
COMP_D_MINUS_1="D-1"
COMP_A_MINUS_1="A-1"
COMP_D_PLUS_A="D+A"
COMP_D_MINUS_A="D-A"
COMP_A_MINUS_D="A-D"
COMP_D_AND_A="D&A"
COMP_D_OR_A="D|A"

COMP_M="M"
COMP_NOT_M="!M"
COMP_NEG_M="-M"
COMP_M_PLUS_1="M+1"
COMP_M_MINUS_1="M-1"
COMP_D_PLUS_M="D+M"
COMP_D_MINUS_M="D-M"
COMP_M_MINUS_D="M-D"
COMP_D_AND_M="D&M"
COMP_D_OR_M="D|M"

LEGAL_COMP = (COMP_0, COMP_1, COMP_NEG_1, COMP_D, COMP_A, COMP_NOT_D,
              COMP_NOT_A, COMP_NEG_D, COMP_NEG_A, COMP_D_PLUS_1, COMP_A_PLUS_1,
              COMP_D_MINUS_1, COMP_A_MINUS_1, COMP_D_PLUS_A, COMP_D_MINUS_A,
              COMP_A_MINUS_D, COMP_D_AND_A, COMP_D_OR_A, COMP_M, COMP_NOT_M,
              COMP_NEG_M, COMP_M_PLUS_1, COMP_M_MINUS_1, COMP_D_PLUS_M,
              COMP_D_MINUS_M, COMP_M_MINUS_D, COMP_D_AND_M, COMP_D_OR_M)



C_INSTRUCTION_MASK = (0b11100000 << 8) # First three bits
A_INSTRUCTION_MASK = (0b10000000 << 8) # First bit

JUMP_OFFSET = 0
DEST_OFFSET = 3
COMP_OFFSET = 6

COMP_MASK = {
    COMP_0 : "0101010",
    COMP_1 : "0111111",
    COMP_NEG_1 : "0111010",
    COMP_D : "0001100",
    COMP_A : "0110000",
    COMP_NOT_D : "0001101",
    COMP_NOT_A : "0110001",
    COMP_NEG_D : "0001111",
    COMP_NEG_A : "0110011",
    COMP_D_PLUS_1 : "0011111",
    COMP_A_PLUS_1 : "0110111",
    COMP_D_MINUS_1 : "0001110",
    COMP_A_MINUS_1 : "0110010",
    COMP_D_PLUS_A : "0000010",
    COMP_D_MINUS_A : "0010011",
    COMP_A_MINUS_D : "0000111",
    COMP_D_AND_A : "0000000",
    COMP_D_OR_A : "0010101",

    COMP_M : "1110000",
    COMP_NOT_M : "1110001",
    COMP_NEG_M : "1110011",
    COMP_M_PLUS_1 : "1110111",
    COMP_M_MINUS_1 : "1110010",
    COMP_D_PLUS_M : "1000010",
    COMP_D_MINUS_M : "1010011",
    COMP_M_MINUS_D : "1000111",
    COMP_D_AND_M : "1000000",
    COMP_D_OR_M : "1010101"
}

assert any(len(mask) != 7 for mask in COMP_MASK)
COMP_MASK = dict((instruction, int(mask, 2)) for (instruction, mask) in COMP_MASK.iteritems())


class AInstruction(object):

    def __init__(self):
        self.mnemonic = LOAD
        self.feature = CF_CHG1 | CF_USE2

    def get_operands(self, instruction):
        return

class CInstruction(object):
    def __init__(self, compute, destination, jump):
        self.compute = compute
        self.destination = destination
        self.jump = jump

    @property
    def mnemonic(self):
        result = ""
        if self.destination != DEST_null:
            result += self.destination + DST_SEP

        result += self.compute

        if self.jump != JUMP_null:
            result += JMP_SEP + self.jump

        return result

    @property
    def feature(self):
        result = 0
        if self.jump != JUMP_null:
            result |= CF_STOP

        for (_, mask) in self.get_feature_mask():
            result |= mask

        return result

    def get_instruction_u16(self):
        instruction = C_INSTRUCTION_MASK

        jump_index = LEGAL_JUMP.index(self.jump)
        instruction |= jump_index << JUMP_OFFSET

        dest_index = LEGAL_DEST.index(self.destination)
        instruction |=  dest_index << DEST_OFFSET

        comp_mask = COMP_MASK[self.compute]
        instruction |= comp_mask << COMP_OFFSET
        return instruction


    def get_feature_mask(self):
        """
        Retrun all the register participate in this instruction.
        :return: List of registers and the their masks
        """
        # Note that we can only use at most two operands, but modify
        # three.
        used_mask = [CF_USE1, CF_USE2]
        modified_mask = [CF_CHG1, CF_CHG2, CF_CHG3]

        operands = []
        for reg in LEGAL_REGS:
            mask = 0
            if reg in self.compute:
                mask |= used_mask.pop(0)

            if reg in self.destination:
                mask |= modified_mask.pop(0)

            if mask:
                operands.append((reg, mask))

        return operands

    def get_operands(self):
        """
        Return the registers participate in this instruction.
        """
        return (reg for (reg, _) in self.get_feature_mask())


a_instruction = AInstruction()

c_instructions = [
    CInstruction(compute, destination, jump) for
    (compute, destination, jump) in
    itertools.product(LEGAL_COMP, LEGAL_DEST, LEGAL_JUMP)
]

all_instructions = [a_instruction] + c_instructions

u16_to_c_instruction = dict(
    [(instruction.get_instruction_u16(), all_instructions.index(instruction))
     for instruction in c_instructions
    ])



SHORT_DESCRIPTION = "n2t-hack"
LONG_DESCRIPTION = "Nanad2Tetris Hack Machine Language"
FAKE_CS = "CS"
FAKE_DS = "DS"

class HackProcessor(processor_t):
    id =  0x8000 + 1023

    # TODO: relevant flags maybe
    # PR_STACK_UP
    # PR_BINMEM
    flag = PRN_BIN
    cnbits = 16
    dnbits = 16

    instruc_start = 0
    instruc_end = len(all_instructions)
    instruc = [{'name': instruction.mnemonic, 'feature': instruction.feature}
               for instruction in all_instructions]


    reg_names = regNames = LEGAL_REGS + [FAKE_CS, FAKE_DS]

    # XXX: Simulate fake segment registers. (No segment register in Hack, but
    # IDA requires them so ..)
    segreg_size = 0
    regFirstSreg = regCodeSreg = reg_names.index(FAKE_CS)
    regLastSreg = regDataSreg = reg_names.index(FAKE_DS)


    psnames = [SHORT_DESCRIPTION]
    plnames = [LONG_DESCRIPTION]


    assembler = {
        "name": LONG_DESCRIPTION,
        "flag" : ASH_HEXF3 | ASD_DECF0| ASO_OCTF4 | ASB_BINF3 | AS_ASCIIC | AS_ASCIIZ ,

        # TODO: verify what necessary
        "uflag": 0,
        "origin": ".org",
        "end": "end",
        "cmnt": ";",

        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",

        "a_ascii": ".ascii",
        "a_byte": ".word",
        "a_word": ".dword",

        "a_bss": "dfs %s",

        "a_seg": "seg",
        "a_curip": ".",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extrn",
        "a_comdef": "",
        "a_align": ".align",

        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    def notify_init(self, idp_file):
        """Called at module initialization."""
        cvar.inf.mf = True  # set to big endian... wtf
        cvar.inf.wide_high_byte_first = True  # big endian for 16b bytes too
        return True

    def ana(self):
        return 0
        cmd = self.cmd

        # Since we set the byte size to be 16 bit.
        instruction = get_16bit(cmd.ea)
        cmd.size = 1

        # Intialize operands.
        operands = [cmd[i] for i in xrange(6)]
        for to_fill in operands:
            to_fill.type = o_void

        if instruction & C_INSTRUCTION_MASK == C_INSTRUCTION_MASK:
            # C - Instruction
            cmd.itype = u16_to_c_instruction[instruction]
            c_instruction = all_instructions[cmd.itype]
            assert c_instruction in c_instructions

            for i, reg in enumerate(c_instruction.get_operands()):
                operands[i].type = o_reg
                operands[i].reg = LEGAL_REGS.index(reg)
                operands[i].dtype = dt_byte

        elif (instruction & A_INSTRUCTION_MASK ) == 0:
            # A - Instruction
            cmd.itype = all_instructions.index(a_instruction)

            operands[0].type = o_reg
            operands[0].dtype = dt_byte
            operands[0].reg = LEGAL_REGS.index(REG_A)

            operands[1].type = o_imm
            operands[1].dtype = dt_byte

            # treat the entire value except the MSB.
            operands[1].value = instruction & (2**(16 - 1) - 1)

        else:
            print "Invalid instruction. %s" % bin(instruction)
            return 0

        setattr(self, 'xx', getattr(self, 'xx', 0) + 1)
        print
        print self.xx
        print bin(instruction)[2:].zfill(16),
        print all_instructions[cmd.itype].mnemonic
        return cmd.size

    def emu(self):
        return True


    def out(self):
        return
        buf = idaapi.init_output_buffer(1024)
        instruction = all_instructions[self.cmd.itype]
        idaapi.MakeLine(instruction.mnemonic)

    def outop(self, op):
        return  True


def PROCESSOR_ENTRY():
    return HackProcessor()
