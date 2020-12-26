#! /usr/bin/python3
# ebpf.py
#
# Specification of ebpf instructions in XIR/Python.

#TODO: use 2-s complement arithmetic, opt-in to mod behaviour, etc.

from xlatxir.xir.anno import xirdecl

def htole16(a: u16) -> u16: ...
def htole32(a: u32) -> u32: ...
def htole64(a: u64) -> u64: ...

def htobe16(a: u16) -> u16: ...
def htobe32(a: u32) -> u32: ...
def htobe64(a: u64) -> u64: ...

def EBPF_OP_ADD(a: b32, b: b32) -> b32:
    return a + b

def EBPF_OP_SUB(a: b32, b: b32) -> b32:
    return a - b

def EBPF_OP_MUL(a: b32, b: b32) -> b32:
    #TODO: make xir pickup return type declaration instead of requiring dst
    dst: b32 = a * b
    return dst

def EBPF_OP_DIV(a: b32, b: b32) -> b32:
    return a // b

def EBPF_OP_OR(a: b32, b: b32) -> b32:
    return a | b

def EBPF_OP_AND(a: b32, b: b32) -> b32:
    return a & b

def EBPF_OP_LSH(value: u32, shift: u32) -> u32:
    return value << shift

def EBPF_OP_RSH(value: u32, shift: u32) -> u32:
    return value >> shift

def EBPF_OP_NEG(value: u32) -> u32:
    return ~value

def EBPF_OP_MOD(a: b32, b: b32) -> b32:
    return a % b

def EBPF_OP_XOR(a: b32, b: b32) -> b32:
    return a ^ b

def EBPF_OP_MOV(a: b32) -> b32:
    return a

def EBPF_OP_ARSH(value: s32, shift: u32) -> s32:
    return value >> shift

def EBPF_OP_LE(value: u64, size: u32) -> u64:
    if size == 16:
        dst = zext(htole16(truncate(value, 16)), 64)
    elif size == 32:
        dst = zext(htole32(truncate(value, 32)), 64)
    elif size == 64:
        dst = htole64(value)
    else:
        #TODO: defined?
        dst = value

    return dst

def EBPF_OP_BE(value: u64, size: u32) -> u64:
    if size == 16:
        dst = zext(htobe16(truncate(value, 16)), 64)
    elif size == 32:
        dst = zext(htobe32(truncate(value, 32)), 64)
    elif size == 64:
        dst = htobe64(value)
    else:
        #TODO: defined?
        dst = value

    return dst

def EBPF_OP_ADD64(a: b64, b: b64) -> b64:
    return a + b

def EBPF_OP_SUB64(a: b64, b: b64) -> b64:
    return a - b

def EBPF_OP_MUL64(a: b64, b: b64) -> b64:
    #TODO: make xir pickup return type declaration instead of requiring dst
    dst: b64 = a * b
    return dst

def EBPF_OP_DIV64(a: b64, b: b64) -> b64:
    return a // b

def EBPF_OP_OR64(a: b64, b: b64) -> b64:
    return a | b

def EBPF_OP_AND64(a: b64, b: b64) -> b64:
    return a & b

def EBPF_OP_LSH64(value: u64, shift: u64) -> u64:
    return value << shift

def EBPF_OP_RSH64(value: u64, shift: u64) -> u64:
    return value >> shift

def EBPF_OP_NEG64(value: u64) -> u64:
    return ~value

def EBPF_OP_MOD64(a: b64, b: b64) -> b64:
    return a % b

def EBPF_OP_XOR64(a: b64, b: b64) -> b64:
    return a ^ b

def EBPF_OP_MOV64(a: b64) -> b64:
    return a

def EBPF_OP_ARSH64(value: s64, shift: u64) -> s64:
    return value >> shift

def EBPF_OP_JA(pc: u16, offset: u16) -> u16:
    return pc + offset

def EPBF_OP_JEQ(pc: u16, offset: u16, a: u64, b: u64) -> u16:
    # is b sign-extended to 64-bits when passed as an immediate (JEQ_IMM) in vm?
    if a == b:
        dst = pc + offset
    else:
        dst = pc

    return dst

def EPBF_OP_JGT(pc: u16, offset: u16, a: u64, b: u64) -> u16:
    # b should not be sign-extended to 64-bits when passed as an immediate (JGT_IMM)
    # TODO: need to be able to write this as pc += offset, waiting for params bugfix for smt2 backend
    if a > b:
        dst = pc + offset
    else:
        dst = pc

    return pc

def EPBF_OP_JGE(pc: u16, offset: u16, a: u64, b: u64) -> u16:
    # b should not be sign-extended to 64-bits when passed as an immediate (JGE_IMM)
    if a >= b:
        dst = pc + offset
    else:
        dst = pc

    return dst

def EPBF_OP_JSET(pc: u16, offset: u16, a: u64, b: u64) -> u16:
    # sign-extension of b unclear
    if (a & b) != 0:
        dst = pc + offset
    else:
        dst = pc

    return dst

def EPBF_OP_JNE(pc: u16, offset: u16, a: u64, b: u64) -> u16:
    # sign extension of b unclear in spec
    if a != b:
        dst = pc + offset
    else:
        dst = pc

    return dst

def EPBF_OP_JSGT(pc: u16, offset: u16, a: s64, b: s64) -> u16:
    if a > b:
        dst = pc + offset
    else:
        dst = pc

    return dst

def EPBF_OP_JSGE(pc: u16, offset: u16, a: s64, b: s64) -> u16:
    if a >= b:
        dst = pc + offset
    else:
        dst = pc

    return dst

# call
# exit

def EPBF_OP_JLT(pc: u16, offset: u16, a: u64, b: u64) -> u16:
    # b should not be sign-extended to 64-bits when passed as an immediate (JLT_IMM)
    if a < b:
        dst = pc + offset
    else:
        dst = pc

    return dst


def EPBF_OP_JLE(pc: u16, offset: u16, a: u64, b: u64) -> u16:
    # b should not be sign-extended to 64-bits when passed as an immediate (JLE_IMM)
    if a <= b:
        dst = pc + offset
    else:
        dst = pc

    return dst


def EPBF_OP_JSLT(pc: u16, offset: u16, a: s64, b: s64) -> u16:
    if a < b:
        dst = pc + offset
    else:
        dst = pc

    return dst

def EPBF_OP_JSLE(pc: u16, offset: u16, a: s64, b: s64) -> u16:
    if a <= b:
        dst = pc + offset
    else:
        dst = pc

    return dst
