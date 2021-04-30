#############################################################
# Onion.py
#
# This is a programing challenge, not even sure what it is
# or why I'm messing with it, it is what it is...
#
# Created to improve my Python skills.
#
# Source Website: https://www.tomdalling.com/toms-data-onion/
#
# Author: Arlen McDonald
# 4/3/2021
#
# Notes:
#
# Outputs a text file for each layer.
#
# For charset I use UTF-8 because it is 8 bit,
# I think any 8 bit char set will work,
# the default ascii for python seems to be 7 bit.
#
#
############################################################
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, _unwrap_core


def trim(t_str):
    """Trim down to the payload, delimited by <~ and ~>, adobe version."""
    t_str = t_str[t_str.index("ayload ]"):]  # Drop the header first, could contain stray markers...
    t_str = t_str[t_str.index("<~"):]
    t_str = t_str[:t_str.index("~>") + 2]
    t_str = t_str.replace("z", "!!!!!")  # Part of the spec, but not sure if it is needed...
    pad(t_str)
    return t_str


def pad(t_str):
    """Pad the string with u so they are even groups of five, part of the spec, but not sure if it is needed."""
    t_str = t_str[:t_str.index("~>")]
    if len(t_str) - 2 % 5 == 1:
        t_str = t_str + "uuuu"
    if len(t_str) - 2 % 5 == 2:
        t_str = t_str + "uuu"
    if len(t_str) - 2 % 5 == 3:
        t_str = t_str + "uu"
    if len(t_str) - 2 % 5 == 4:
        t_str = t_str + "u"
    return t_str + "~>"


def decode(t_str):
    """Decode using Adobe85, strip out whitespace, line-feeds, and control characters.

    Every layer needs this as a pre-process."""
    return base64.a85decode(t_str, adobe=True, foldspaces=False, ignorechars=b' \n\r\t\v\\s\0')


def writeF(t_str, name):
    """Write out results to a file, UTF-8 encoded."""
    with open(name, "w", ) as f2:
        f2.write(t_str.decode("utf-8"))


def writeF2(t_str, name):
    """Write out results to a file, no encoding."""
    with open(name, "w", ) as f2:
        f2.write(t_str)


def parity_test(byt):
    """Test parity bit of a byte vs actual parity, return boolean."""
    pty = byt & 1
    byt >>= 1
    if parity(byt) == pty:
        return True
    return False


def parity(x):
    """Determine parity of a byte, return 0 for even, 1 for odd."""
    # Found at: https://stackoverflow.com/questions/57548852/checking-parity-of-a-number-in-python
    res = 0
    while x:
        res ^= x & 1
        x >>= 1
    return res


def bytestr(tb: bytes):
    """Bytes to string, return a string representing a 7 bit binary number."""
    ts = ""
    tb >>= 1
    for x in range(7):
        ts = str(tb & 1) + ts  # Remove the last bit and add it to the front of the string.
        tb >>= 1
    return ts


def packetize(pktstr):
    """Return an array of bytearray packets from a single bytearray."""
    idx = 0
    pktary = []
    while idx < len(pktstr):
        if pktstr[idx] == 69:
            leng = int.from_bytes(pktstr[idx + 3:idx + 4], byteorder="big", signed=False)
            pktary.append(pktstr[idx:idx + leng])
            idx += leng
        else:
            idx += 1
    return pktary


def depacketize(pktary):
    """Return payload data from an array of packets."""
    pl = ""
    for x in range(len(pktary)):
        leng = int.from_bytes(pktary[x][24:26], byteorder="big", signed=False)
        pl += bytearray(pktary[x][28:28 + leng]).decode("utf-8")
    return pl


def srciptest(pkt, a, b, c, d):
    """Determine if source IP address matches input."""
    if pkt[12] == a and pkt[13] == b and pkt[14] == c and pkt[15] == d:
        return True
    return False


def destiptest(pkt, a, b, c, d):
    """Determine if destination IP address matches input."""
    if pkt[16] == a and pkt[17] == b and pkt[18] == c and pkt[19] == d:
        return True
    return False


def getdestport(pkt):
    """Return destination port of input packet."""
    port = int.from_bytes(pkt[22:24], byteorder="big", signed=False)
    return port


def iphdrcs(pkt):
    """Test if IPv4 header checksum is valid."""
    tot = 0
    for x in range(0, 19, 2):
        tot += int.from_bytes(pkt[x:x + 2], byteorder="big", signed=False)
    if onesComplement16(tot) == 0:  # One's complement of total should equal 0.
        return True
    return False


def udphdrcs(pkt):
    """Test if UDP header checksum is valid."""

    # Create Pseudo Header
    p_hdr = bytearray()
    for x in range(12, 20):
        p_hdr.append(pkt[x])  # Src and Dest addresses.
    p_hdr.append(0)        # Pad
    p_hdr.append(pkt[9])   # Protocol
    p_hdr.append(pkt[24])  # Length of payload
    p_hdr.append(pkt[25])
    for x in range(20, 28):
        p_hdr.append(pkt[x])  # Src and Dest ports, Length of payload again, UDP Checksum.
    for x in range(28, len(pkt)):
        p_hdr.append(pkt[x])  # Payload

    # Check length of payload and pad if odd, need 16 bit groups.
    leng = int.from_bytes(pkt[24:26], byteorder="big", signed=False)
    if leng % 2 != 0:
        leng += 1
        p_hdr.append(0)  # Pad

    # Total 16 bit words in Pseudo Header
    tot = 0
    for x in range(0, len(p_hdr), 2):
        tot += int.from_bytes(p_hdr[x:x + 2], byteorder="big", signed=False)
    tot = (tot & 0xFFFF) + (tot >> 16)  # Wrap anything that overflows 16 bit.
    tot = (tot & 0xFFFF) + (tot >> 16)  # The add could cause a second overflow.

    # One's complement of total, should equal 0.
    if onesComplement16(tot) == 0:
        return True
    return False


def onesComplement16(n):
    """One's Complement of a number, 16 bit words only."""
    return ~n & 0xffff  # Invert, then and to get rid of the sign bit.


def key_unwrap(wrapping_key, wrapping_iv, wrapped_key, backend):
    """AES Key Unwrap algorithm, implements RFC 3394."""
    # Copied from: https://cryptography.io/en/2.5/_modules/cryptography/hazmat/primitives/keywrap/
    if len(wrapped_key) < 24:
        raise InvalidUnwrap("Must be at least 24 bytes")

    if len(wrapped_key) % 8 != 0:
        raise InvalidUnwrap("The wrapped key must be a multiple of 8 bytes")

    if len(wrapping_key) not in [16, 24, 32]:
        raise ValueError("The wrapping key must be a valid AES key length")

    r = [wrapped_key[j:j + 8] for j in range(0, len(wrapped_key), 8)]
    a = r.pop(0)
    a, r = _unwrap_core(wrapping_key, a, r, backend)
    if bytes_eq(a, bytes(wrapping_iv)) is False:
        raise InvalidUnwrap()

    return b"".join(r)


def vm(memory, debug):
    """Virtual machine to interpret given bytecode and return text."""
    out_stream = ""

    # 8-Bit Registers
    a = 0  # Accumulator
    b = 0  # Operand Register
    c = 0  # Count/Offset Register
    d = 0  # General Purpose Register
    e = 0  # General Purpose Register
    f = 0  # Flags Register
    # 32-Bit Registers
    la = 0  # General Purpose Register
    lb = 0  # General Purpose Register
    lc = 0  # General Purpose Register
    ld = 0  # General Purpose Register
    ptr = 0  # Pointer to Memory
    pc = 0  # Program Counter
    # Pseudo Register
    ptrc = 0  # Memory Cursor

    eop = len(memory)  # End of Program Flag


    # Main loop
    # No switch statement???  This is going to be awkward looking....
    while pc < eop:
        if memory[pc] == 0xC2:  # ADD a <- b, 8-bit addition
            if debug:
                print("Add")
            pc += 1
        elif memory[pc] == 0xE1:  # APTR imm8, Advance pointer
            if debug:
                print("APTR ", memory[pc + 1])
            ptr += memory[pc+1]
            pc += 2
        elif memory[pc] == 0xc1:  # CMP, Compare a and b, results in f.
            if debug:
                print("CMP", f)
            pc += 1
        elif memory[pc] == 0x01:  # HALT, Halt execution.
            if debug:
                print("HALT")
            pc = eop  # Hop to end of program.
            #pc += 1
        elif memory[pc] == 0x21:  # JEZ imm32, Jump if equals zero, determined by f.
            if debug:
                print("JEZ ", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            pc += 5
        elif memory[pc] == 0x22:  # JNZ imm32, Jump if not zero, determined by f.
            if debug:
                print("JNZ ", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            pc += 5
        elif memory[pc] == 0b01001010:  # MV {dest} <- {src}, Move 8-bit value, b to a.
            if debug:
                print("MV  a <- b")
            pc += 1
        elif memory[pc] == 0b01001011:  # MV {dest} <- {src}, Move 8-bit value, c to a.
            if debug:
                print("MV  a <- c")
            pc += 1
        elif memory[pc] == 0b01001100:  # MV {dest} <- {src}, Move 8-bit value, d to a.
            if debug:
                print("MV  a <- d")
            pc += 1
        elif memory[pc] == 0b01001101:  # MV {dest} <- {src}, Move 8-bit value, e to a.
            if debug:
                print("MV  a <- e")
            pc += 1
        elif memory[pc] == 0b01001110:  # MV {dest} <- {src}, Move 8-bit value, f to a.
            if debug:
                print("MV  a <- f")
            pc += 1
        elif memory[pc] == 0b01001111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to a.
            if debug:
                print("MV  a <- (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01010001:  # MV {dest} <- {src}, Move 8-bit value, a to b.
            if debug:
                print("MV  b <- a")
            pc += 1
        elif memory[pc] == 0b01010011:  # MV {dest} <- {src}, Move 8-bit value, c to b.
            if debug:
                print("MV  b <- c")
            pc += 1
        elif memory[pc] == 0b01010100:  # MV {dest} <- {src}, Move 8-bit value, d to b.
            if debug:
                print("MV  b <- d")
            pc += 1
        elif memory[pc] == 0b01010101:  # MV {dest} <- {src}, Move 8-bit value, e to b.
            if debug:
                print("MV  b <- e")
            pc += 1
        elif memory[pc] == 0b01010110:  # MV {dest} <- {src}, Move 8-bit value, f to b.
            if debug:
                print("MV  b <- f")
            pc += 1
        elif memory[pc] == 0b01010111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to b.
            if debug:
                print("MV  b <- (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01011001:  # MV {dest} <- {src}, Move 8-bit value, a to c.
            if debug:
                print("MV a to c")
            pc += 1
        elif memory[pc] == 0b01011010:  # MV {dest} <- {src}, Move 8-bit value, b to c.
            if debug:
                print("MV b to c")
            pc += 1
        elif memory[pc] == 0b01011100:  # MV {dest} <- {src}, Move 8-bit value, d to c.
            if debug:
                print("MV d to c")
            pc += 1
        elif memory[pc] == 0b01011101:  # MV {dest} <- {src}, Move 8-bit value, e to c.
            if debug:
                print("MV e to c")
            pc += 1
        elif memory[pc] == 0b01011110:  # MV {dest} <- {src}, Move 8-bit value, f to c.
            if debug:
                print("MV f to c")
            pc += 1
        elif memory[pc] == 0b01011111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to c.
            if debug:
                print("MV (ptr+c) to c")
            pc += 1
        elif memory[pc] == 0b01100001:  # MV {dest} <- {src}, Move 8-bit value, a to d.
            if debug:
                print("MV a to d")
            pc += 1
        elif memory[pc] == 0b01100010:  # MV {dest} <- {src}, Move 8-bit value, b to d.
            if debug:
                print("MV b to d")
            pc += 1
        elif memory[pc] == 0b01100011:  # MV {dest} <- {src}, Move 8-bit value, c to d.
            if debug:
                print("MV c to d")
            pc += 1
        elif memory[pc] == 0b01100101:  # MV {dest} <- {src}, Move 8-bit value, e to d.
            if debug:
                print("MV e to d")
            pc += 1
        elif memory[pc] == 0b01100110:  # MV {dest} <- {src}, Move 8-bit value, f to d.
            if debug:
                print("MV f to d")
            pc += 1
        elif memory[pc] == 0b01100111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to d.
            if debug:
                print("MV (ptr+c) to d")
            pc += 1
        elif memory[pc] == 0b01101001:  # MV {dest} <- {src}, Move 8-bit value, a to e.
            if debug:
                print("MV a to e")
            pc += 1
        elif memory[pc] == 0b01101010:  # MV {dest} <- {src}, Move 8-bit value, b to e.
            if debug:
                print("MV b to e")
            pc += 1
        elif memory[pc] == 0b01101011:  # MV {dest} <- {src}, Move 8-bit value, c to e.
            if debug:
                print("MV c to e")
            pc += 1
        elif memory[pc] == 0b01101100:  # MV {dest} <- {src}, Move 8-bit value, d to e.
            if debug:
                print("MV d to e")
            pc += 1
        elif memory[pc] == 0b01101110:  # MV {dest} <- {src}, Move 8-bit value, f to e.
            if debug:
                print("MV f to e")
            pc += 1
        elif memory[pc] == 0b01101111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to e.
            if debug:
                print("MV (ptr+c) to e")
            pc += 1
        elif memory[pc] == 0b01110001:  # MV {dest} <- {src}, Move 8-bit value, a to f.
            if debug:
                print("MV a to f")
            pc += 1
        elif memory[pc] == 0b01110010:  # MV {dest} <- {src}, Move 8-bit value, b to f.
            if debug:
                print("MV b to f")
            pc += 1
        elif memory[pc] == 0b01110011:  # MV {dest} <- {src}, Move 8-bit value, c to f.
            if debug:
                print("MV c to f")
            pc += 1
        elif memory[pc] == 0b01110100:  # MV {dest} <- {src}, Move 8-bit value, d to f.
            if debug:
                print("MV d to f")
            pc += 1
        elif memory[pc] == 0b01110101:  # MV {dest} <- {src}, Move 8-bit value, e to f.
            if debug:
                print("MV e to f")
            pc += 1
        elif memory[pc] == 0b01110111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to f.
            if debug:
                print("MV (ptr+c) to f")
            pc += 1
        elif memory[pc] == 0b01111001:  # MV {dest} <- {src}, Move 8-bit value, a to (ptr+c).
            if debug:
                print("MV a to (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01111010:  # MV {dest} <- {src}, Move 8-bit value, b to (ptr+c).
            if debug:
                print("MV b to (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01111011:  # MV {dest} <- {src}, Move 8-bit value, c to (ptr+c).
            if debug:
                print("MV c to (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01111100:  # MV {dest} <- {src}, Move 8-bit value, d to (ptr+c).
            if debug:
                print("MV d to (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01111101:  # MV {dest} <- {src}, Move 8-bit value, e to (ptr+c).
            if debug:
                print("MV e to (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01111110:  # MV {dest} <- {src}, Move 8-bit value, f to (ptr+c).
            if debug:
                print("MV f to (ptr+c)")
            pc += 1
        elif memory[pc] == 0b01001000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to a.
            if debug:
                print("MVI  a <-", memory[pc+1])
            a = memory[pc+1]
            pc += 2
        elif memory[pc] == 0b01010000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to b.
            if debug:
                print("MVI  b <-", memory[pc+1])
            b = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01011000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to c.
            if debug:
                print("MVI  c <-", memory[pc+1])
            c = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01100000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to d.
            if debug:
                print("MVI  d <-", memory[pc+1])
            d = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01101000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to e.
            if debug:
                print("MVI  e <-", memory[pc+1])
            e = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01110000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to f.
            if debug:
                print("MVI  f <-", memory[pc+1])
            f = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01111000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to (ptr+c).
            if debug:
                print("MVI  (ptr+c) <-", memory[pc+1])
            ptrc = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b10001000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to la.
            if debug:
                print("MVI32  la <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            la = int.from_bytes(memory[pc+1:pc+5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10010000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to lb.
            if debug:
                print("MVI32  lb <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            lb = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10011000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to lc.
            if debug:
                print("MVI32  lc <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            lc = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10100000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to ld.
            if debug:
                print("MVI32  ld <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            ld = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10101000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to ptr.
            if debug:
                print("MVI32  ptr <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            ptr = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10110000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to pc.
            if debug:
                print("MVI32  pc <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            pc = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
        elif memory[pc] == 0b10001010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to la.
            if debug:
                print("MV32  la <- lb")
            la = lb
            pc += 1
        elif memory[pc] == 0b10001011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to la.
            if debug:
                print("MV32  la <- lc")
            la = lc
            pc += 1
        elif memory[pc] == 0b10001100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to la.
            if debug:
                print("MV32  la <- ld")
            la = ld
            pc += 1
        elif memory[pc] == 0b10001101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to la.
            if debug:
                print("MV32  la <- ptr")
            la = ptr
            pc += 1
        elif memory[pc] == 0b10001110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to la.
            if debug:
                print("MV32  la <- pc")
            la = pc
            pc += 1
        elif memory[pc] == 0b10010001:  # MV32 {dest} <- {src}, Move 32-bit value, la to lb.
            if debug:
                print("MV32  lb <- la")
            lb = la
            pc += 1
        elif memory[pc] == 0b10010011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to lb.
            if debug:
                print("MV32  lb <- lc")
            lb = lc
            pc += 1
        elif memory[pc] == 0b10010100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to lb.
            if debug:
                print("MV32  lb <- ld")
            lb = ld
            pc += 1
        elif memory[pc] == 0b10010101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to lb.
            if debug:
                print("MV32  lb <- ptr")
            lb = ptr
            pc += 1
        elif memory[pc] == 0b10010110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to lb.
            if debug:
                print("MV32  lb <- pc")
            lb = pc
            pc += 1
        elif memory[pc] == 0b10011001:  # MV32 {dest} <- {src}, Move 32-bit value, la to lc.
            if debug:
                print("MV32 la to lc")
            pc += 1
        elif memory[pc] == 0b10011010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to lc.
            if debug:
                print("MV32 lb to lc")
            pc += 1
        elif memory[pc] == 0b10011100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to lc.
            if debug:
                print("MV32 ld to lc")
            pc += 1
        elif memory[pc] == 0b10011101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to lc.
            if debug:
                print("MV32 ptr to lc")
            pc += 1
        elif memory[pc] == 0b10011110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to lc.
            if debug:
                print("MV32 pc to lc")
            pc += 1
        elif memory[pc] == 0b10100001:  # MV32 {dest} <- {src}, Move 32-bit value, la to ld.
            if debug:
                print("MV32 la to ld")
            pc += 1
        elif memory[pc] == 0b10100010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to ld.
            if debug:
                print("MV32 lb to ld")
            pc += 1
        elif memory[pc] == 0b10100011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to ld.
            if debug:
                print("MV32 lc to ld")
            pc += 1
        elif memory[pc] == 0b10100101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to ld.
            if debug:
                print("MV32 ptr to ld")
            pc += 1
        elif memory[pc] == 0b10100110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to ld.
            if debug:
                print("MV32 pc to ld")
            pc += 1
        elif memory[pc] == 0b10101001:  # MV32 {dest} <- {src}, Move 32-bit value, la to ptr.
            if debug:
                print("MV32 la to ptr")
            pc += 1
        elif memory[pc] == 0b10101010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to ptr.
            if debug:
                print("MV32 lb to ptr")
            pc += 1
        elif memory[pc] == 0b10101011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to ptr.
            if debug:
                print("MV32 lc to ptr")
            pc += 1
        elif memory[pc] == 0b10101100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to ptr.
            if debug:
                print("MV32 ld to ptr")
            pc += 1
        elif memory[pc] == 0b10101110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to ptr.
            if debug:
                print("MV32 pc to ptr")
            pc += 1
        elif memory[pc] == 0b10110001:  # MV32 {dest} <- {src}, Move 32-bit value, la to pc.
            if debug:
                print("MV32 la to pc")
            pc += 1
        elif memory[pc] == 0b10110010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to pc.
            if debug:
                print("MV32 lb to pc")
            pc += 1
        elif memory[pc] == 0b10110011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to pc.
            if debug:
                print("MV32 lc to pc")
            pc += 1
        elif memory[pc] == 0b10110100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to pc.
            if debug:
                print("MV32 ld to pc")
            pc += 1
        elif memory[pc] == 0b10110101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to pc.
            if debug:
                print("MV32 ptr to pc")
            pc += 1
        elif memory[pc] == 0x02:  # OUT, Output byte, value of a.
            if debug:
                print("OUT", a)
            out_stream += str(a)
            pc += 1
        elif memory[pc] == 0xC3:  # SUB a <- b, 8-bit subtraction, b from a.
            if debug:
                print("SUB")
            pc += 1
        elif memory[pc] == 0xC4:  # XOR a <- b, 8-bit bitwise exclusive OR, b XOR a.
            if debug:
                print("XOR")
            pc += 1
        else:
            if debug:
                print("Invalid Instruction", memory[pc])
            pc += 1

    return out_stream


# Main - Initialize
with open("onion.txt") as f:  # Read only
    in_f = f.read()


# Layer 0 - ASCII85
payL = decode(trim(in_f))
writeF(payL, "onion1.txt")


# Layer 1 - Bitwise Operations
payL = decode(trim(payL.decode("utf-8")))
ba = bytearray(payL)  # Need bytes for bit manipulation.
for i in range(len(ba)):
    ba[i] ^= 0b01010101  # XOR to flip every other bit, 01010101 = 85.
    ba[i] >>= 1  # Right shift one bit.
payL = bytearray(ba).decode("utf-8")
writeF2(payL, "onion2.txt")


# Layer 2 - Parity Bit
payL = decode(trim(payL))
ba = bytearray(payL)

# Test for bad parity and discard fails
ba2 = bytearray()
for i in ba:
    if parity_test(i):
        ba2.append(i)

# Convert from 8, 7 bit groups to 7, 8 bit groups.  Uses a string of text 1s and 0s as an intermediary step.
ba3 = bytearray()
for i in range(0, len(ba2), 8):
    r_str = bytestr(ba2[i]) + bytestr(ba2[i + 1]) + bytestr(ba2[i + 2]) + bytestr(ba2[i + 3]) \
            + bytestr(ba2[i + 4]) + bytestr(ba2[i + 5]) + bytestr(ba2[i + 6]) + bytestr(ba2[i + 7])  # Bytes to string.
    ba3 = ba3 + bytearray(int(r_str, 2).to_bytes(7, byteorder="big", signed=False))  # String to bytes.

payL = bytearray.decode(bytearray(ba3), "utf-8")
writeF2(payL, "onion3.txt")


# Layer 3 - XOR Encryption
payL = decode(trim(payL))
ba = bytearray(payL)
key = bytearray(b'\x6c\x24\x84\x8e\x42\x19\xa8\xe1'
                b'\xc5\xdb\x57\x65\xb9\xc6\x14\x9e'
                b'\xa5\x19\x35\x96\x3b\x39\x7f\xa5'
                b'\x65\xd1\xfe\x01\x85\x7d\xd9\x4c')  # 32 Byte key, manually derived it.

for i in range(len(ba)):
    ba[i] ^= key[i % 32]  # XOR bytearray with key, 32 byte chunks.
payL = bytearray(ba).decode("utf-8")
writeF2(payL, "onion4.txt")


# Layer 4 - Network Traffic
payL = decode(trim(payL))
ba = bytearray(payL)
packets = packetize(ba)  # Break up into packets
# Filter out bad packets
testing = 0
while testing < len(packets):
    if srciptest(packets[testing], 10, 1, 1, 10) is False \
            or destiptest(packets[testing], 10, 1, 1, 200) is False \
            or getdestport(packets[testing]) != 42069 \
            or iphdrcs(packets[testing]) is False \
            or udphdrcs(packets[testing]) is False:
        packets.pop(testing)
    else:
        testing += 1

payL = depacketize(packets)  # Strip out payload data
writeF2(payL, "onion5.txt")


# layer 5 - Advanced Encryption Standard
payL = decode(trim(payL))
ba = bytearray(payL)
kEK = ba[0:32]  # Key Encrypting Key
kIV = ba[32:40]  # Key Initialization Vector
eKey = ba[40:80]  # Encrypted key
pIV = ba[80:96]  # Payload Initialization Vector
ePayL = ba[96:]  # Encrypted payload
dKey = key_unwrap(wrapping_key=kEK, wrapping_iv=kIV, wrapped_key=eKey, backend=default_backend())
cipher = Cipher(algorithms.AES(dKey), modes.CTR(pIV), backend=default_backend())
payL = cipher.decryptor().update(ePayL).decode("utf-8")
writeF2(payL, "onion6.txt")


# Layer 6 - Virtual Machine
# Test program
hello = bytearray(b'\x50\x48\xC2\x02\xA8\x4D\x00\x00\x00\x4F\x02\x50\x09\xC4\x02\x02'
                  b'\xE1\x01\x4F\x02\xC1\x22\x1D\x00\x00\x00\x48\x30\x02\x58\x03\x4F'
                  b'\x02\xB0\x29\x00\x00\x00\x48\x31\x02\x50\x0C\xC3\x02\xAA\x57\x48'
                  b'\x02\xC1\x21\x3A\x00\x00\x00\x48\x32\x02\x48\x77\x02\x48\x6F\x02'
                  b'\x48\x72\x02\x48\x6C\x02\x48\x64\x02\x48\x21\x02\x01\x65\x6F\x33'
                  b'\x34\x2C')
payL = decode(trim(payL))
ba = bytearray(payL)
#print(vm(ba, True))
print(vm(hello, debug=True))
#payL = bytearray(ba).decode("utf-8")
#print(payL)


# Exit
