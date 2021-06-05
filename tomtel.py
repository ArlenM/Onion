######################################################
# tomtel.py
#
# Implements the Tomtel Core i69 virtual machine,
# from the Tom's Data Onion programming challenge.
#
# Created by: Arlen McDonald
#
# 5/12/21
######################################################
def tomtel_VM(memory, debug):
    """Tomtel Virtual machine to interpret given bytecode and return text.

    Returns a string, set debug to True to monitor execution."""
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
    pc = 0  # Program Counter (Next instruction)
    # Other variables
    eop = len(memory)  # End of Program Flag
    out_stream = ""

    # Main loop
    # No switch statement???  This is going to be awkward looking....
    while pc < eop:
        if memory[pc] == 0xC2:  # ADD a <- b, 8-bit addition
            if debug:
                print("Add", a, b)
            a += b
            a &= 0xFF  # Limit to 8 bits.
            pc += 1
        elif memory[pc] == 0xE1:  # APTR imm8, Advance pointer
            if debug:
                print("APTR", memory[pc + 1])
            ptr += memory[pc + 1]
            pc += 2
        elif memory[pc] == 0xc1:  # CMP, Compare a and b, results in f.
            if debug:
                print("CMP", f)
            if a == b:
                f = 0
            else:
                f = 1
            pc += 1
        elif memory[pc] == 0x01:  # HALT, Halt execution.
            if debug:
                print("HALT")
            pc = eop  # Hop to end of program.
        elif memory[pc] == 0x21:  # JEZ imm32, Jump if equals zero, determined by f.
            if debug:
                print("JEZ", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            if f == 0:
                pc = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            else:
                pc += 5
        elif memory[pc] == 0x22:  # JNZ imm32, Jump if not zero, determined by f.
            if debug:
                print("JNZ", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            if f != 0:
                pc = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            else:
                pc += 5
        elif memory[pc] == 0b01001010:  # MV {dest} <- {src}, Move 8-bit value, b to a.
            if debug:
                print("MV a <- b")
            a = b
            pc += 1
        elif memory[pc] == 0b01001011:  # MV {dest} <- {src}, Move 8-bit value, c to a.
            if debug:
                print("MV a <- c")
            a = c
            pc += 1
        elif memory[pc] == 0b01001100:  # MV {dest} <- {src}, Move 8-bit value, d to a.
            if debug:
                print("MV a <- d")
            a = d
            pc += 1
        elif memory[pc] == 0b01001101:  # MV {dest} <- {src}, Move 8-bit value, e to a.
            if debug:
                print("MV a <- e")
            a = e
            pc += 1
        elif memory[pc] == 0b01001110:  # MV {dest} <- {src}, Move 8-bit value, f to a.
            if debug:
                print("MV a <- f")
            a = f
            pc += 1
        elif memory[pc] == 0b01001111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to a.
            if debug:
                print("MV a <- (ptr+c)")
            a = memory[ptr + c]
            pc += 1
        elif memory[pc] == 0b01010001:  # MV {dest} <- {src}, Move 8-bit value, a to b.
            if debug:
                print("MV b <- a")
            b = a
            pc += 1
        elif memory[pc] == 0b01010011:  # MV {dest} <- {src}, Move 8-bit value, c to b.
            if debug:
                print("MV b <- c")
            b = c
            pc += 1
        elif memory[pc] == 0b01010100:  # MV {dest} <- {src}, Move 8-bit value, d to b.
            if debug:
                print("MV b <- d")
            b = d
            pc += 1
        elif memory[pc] == 0b01010101:  # MV {dest} <- {src}, Move 8-bit value, e to b.
            if debug:
                print("MV b <- e")
            b = e
            pc += 1
        elif memory[pc] == 0b01010110:  # MV {dest} <- {src}, Move 8-bit value, f to b.
            if debug:
                print("MV b <- f")
            pc += 1
        elif memory[pc] == 0b01010111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to b.
            if debug:
                print("MV b <- (ptr+c)")
            b = memory[ptr + c]
            pc += 1
        elif memory[pc] == 0b01011001:  # MV {dest} <- {src}, Move 8-bit value, a to c.
            if debug:
                print("MV c <- a")
            c = a
            pc += 1
        elif memory[pc] == 0b01011010:  # MV {dest} <- {src}, Move 8-bit value, b to c.
            if debug:
                print("MV c <- b")
            c = b
            pc += 1
        elif memory[pc] == 0b01011100:  # MV {dest} <- {src}, Move 8-bit value, d to c.
            if debug:
                print("MV c <- d")
            c = d
            pc += 1
        elif memory[pc] == 0b01011101:  # MV {dest} <- {src}, Move 8-bit value, e to c.
            if debug:
                print("MV c <- e")
            c = e
            pc += 1
        elif memory[pc] == 0b01011110:  # MV {dest} <- {src}, Move 8-bit value, f to c.
            if debug:
                print("MV c <- f")
            c = f
            pc += 1
        elif memory[pc] == 0b01011111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to c.
            if debug:
                print("MV c <- (ptr+c)")
            c = memory[ptr + c]
            pc += 1
        elif memory[pc] == 0b01100001:  # MV {dest} <- {src}, Move 8-bit value, a to d.
            if debug:
                print("MV d <- a")
            d = a
            pc += 1
        elif memory[pc] == 0b01100010:  # MV {dest} <- {src}, Move 8-bit value, b to d.
            if debug:
                print("MV d <- b")
            d = b
            pc += 1
        elif memory[pc] == 0b01100011:  # MV {dest} <- {src}, Move 8-bit value, c to d.
            if debug:
                print("MV d <- c")
            d = c
            pc += 1
        elif memory[pc] == 0b01100101:  # MV {dest} <- {src}, Move 8-bit value, e to d.
            if debug:
                print("MV d <- e")
            d = e
            pc += 1
        elif memory[pc] == 0b01100110:  # MV {dest} <- {src}, Move 8-bit value, f to d.
            if debug:
                print("MV d <- f")
            d = f
            pc += 1
        elif memory[pc] == 0b01100111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to d.
            if debug:
                print("MV d <- (ptr+c)")
            d = memory[ptr + c]
            pc += 1
        elif memory[pc] == 0b01101001:  # MV {dest} <- {src}, Move 8-bit value, a to e.
            if debug:
                print("MV e <- a")
            e = a
            pc += 1
        elif memory[pc] == 0b01101010:  # MV {dest} <- {src}, Move 8-bit value, b to e.
            if debug:
                print("MV e <- b")
            e = b
            pc += 1
        elif memory[pc] == 0b01101011:  # MV {dest} <- {src}, Move 8-bit value, c to e.
            if debug:
                print("MV e <- c")
            e = c
            pc += 1
        elif memory[pc] == 0b01101100:  # MV {dest} <- {src}, Move 8-bit value, d to e.
            if debug:
                print("MV e <- d")
            e = d
            pc += 1
        elif memory[pc] == 0b01101110:  # MV {dest} <- {src}, Move 8-bit value, f to e.
            if debug:
                print("MV e <- f")
            e = f
            pc += 1
        elif memory[pc] == 0b01101111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to e.
            if debug:
                print("MV e <- (ptr+c)")
            e = memory[ptr + c]
            pc += 1
        elif memory[pc] == 0b01110001:  # MV {dest} <- {src}, Move 8-bit value, a to f.
            if debug:
                print("MV f <- a")
            f = a
            pc += 1
        elif memory[pc] == 0b01110010:  # MV {dest} <- {src}, Move 8-bit value, b to f.
            if debug:
                print("MV f <- b")
            f = b
            pc += 1
        elif memory[pc] == 0b01110011:  # MV {dest} <- {src}, Move 8-bit value, c to f.
            if debug:
                print("MV f <- c")
            f = c
            pc += 1
        elif memory[pc] == 0b01110100:  # MV {dest} <- {src}, Move 8-bit value, d to f.
            if debug:
                print("MV f <- d")
            f = d
            pc += 1
        elif memory[pc] == 0b01110101:  # MV {dest} <- {src}, Move 8-bit value, e to f.
            if debug:
                print("MV f <- e")
            f = e
            pc += 1
        elif memory[pc] == 0b01110111:  # MV {dest} <- {src}, Move 8-bit value, (ptr+c) to f.
            if debug:
                print("MV f <- (ptr+c)")
            f = memory[ptr + c]
            pc += 1
        elif memory[pc] == 0b01111001:  # MV {dest} <- {src}, Move 8-bit value, a to (ptr+c).
            if debug:
                print("MV (ptr+c) <- a")
            memory[ptr + c] = a
            pc += 1
        elif memory[pc] == 0b01111010:  # MV {dest} <- {src}, Move 8-bit value, b to (ptr+c).
            if debug:
                print("MV (ptr+c) <- b")
            memory[ptr + c] = b
            pc += 1
        elif memory[pc] == 0b01111011:  # MV {dest} <- {src}, Move 8-bit value, c to (ptr+c).
            if debug:
                print("MV (ptr+c) <- c")
            memory[ptr + c] = c
            pc += 1
        elif memory[pc] == 0b01111100:  # MV {dest} <- {src}, Move 8-bit value, d to (ptr+c).
            if debug:
                print("MV (ptr+c) <- d")
            memory[ptr + c] = d
            pc += 1
        elif memory[pc] == 0b01111101:  # MV {dest} <- {src}, Move 8-bit value, e to (ptr+c).
            if debug:
                print("MV (ptr+c) <- e")
            memory[ptr + c] = e
            pc += 1
        elif memory[pc] == 0b01111110:  # MV {dest} <- {src}, Move 8-bit value, f to (ptr+c).
            if debug:
                print("MV (ptr+c) <- f")
            memory[ptr + c] = f
            pc += 1
        elif memory[pc] == 0b01001000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to a.
            if debug:
                print("MVI a <-", memory[pc+1])
            a = memory[pc+1]
            pc += 2
        elif memory[pc] == 0b01010000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to b.
            if debug:
                print("MVI b <-", memory[pc+1])
            b = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01011000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to c.
            if debug:
                print("MVI c <-", memory[pc+1])
            c = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01100000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to d.
            if debug:
                print("MVI d <-", memory[pc+1])
            d = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01101000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to e.
            if debug:
                print("MVI e <-", memory[pc+1])
            e = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01110000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to f.
            if debug:
                print("MVI f <-", memory[pc+1])
            f = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b01111000:  # MVI {dest} <- imm8, Move 8-bit value, imm8 to (ptr+c).
            if debug:
                print("MVI (ptr+c) <-", memory[pc+1])
            memory[ptr + c] = memory[pc + 1]
            pc += 2
        elif memory[pc] == 0b10001000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to la.
            if debug:
                print("MVI32 la <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            la = int.from_bytes(memory[pc+1:pc+5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10010000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to lb.
            if debug:
                print("MVI32 lb <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            lb = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10011000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to lc.
            if debug:
                print("MVI32 lc <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            lc = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10100000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to ld.
            if debug:
                print("MVI32 ld <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            ld = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10101000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to ptr.
            if debug:
                print("MVI32 ptr <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            ptr = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
            pc += 5
        elif memory[pc] == 0b10110000:  # MVI32 {dest} <- imm32, Move 32-bit value, imm32 to pc.
            if debug:
                print("MVI32 pc <-", memory[pc + 1], memory[pc + 2], memory[pc + 3], memory[pc + 4])
            pc = int.from_bytes(memory[pc + 1:pc + 5], byteorder="little", signed=False)
        elif memory[pc] == 0b10001010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to la.
            if debug:
                print("MV32 la <- lb")
            la = lb
            pc += 1
        elif memory[pc] == 0b10001011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to la.
            if debug:
                print("MV32 la <- lc")
            la = lc
            pc += 1
        elif memory[pc] == 0b10001100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to la.
            if debug:
                print("MV32 la <- ld")
            la = ld
            pc += 1
        elif memory[pc] == 0b10001101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to la.
            if debug:
                print("MV32 la <- ptr")
            la = ptr
            pc += 1
        elif memory[pc] == 0b10001110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to la.
            if debug:
                print("MV32 la <- pc")
            la = pc
            pc += 1
        elif memory[pc] == 0b10010001:  # MV32 {dest} <- {src}, Move 32-bit value, la to lb.
            if debug:
                print("MV32 lb <- la")
            lb = la
            pc += 1
        elif memory[pc] == 0b10010011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to lb.
            if debug:
                print("MV32 lb <- lc")
            lb = lc
            pc += 1
        elif memory[pc] == 0b10010100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to lb.
            if debug:
                print("MV32 lb <- ld")
            lb = ld
            pc += 1
        elif memory[pc] == 0b10010101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to lb.
            if debug:
                print("MV32 lb <- ptr")
            lb = ptr
            pc += 1
        elif memory[pc] == 0b10010110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to lb.
            if debug:
                print("MV32 lb <- pc")
            lb = pc
            pc += 1
        elif memory[pc] == 0b10011001:  # MV32 {dest} <- {src}, Move 32-bit value, la to lc.
            if debug:
                print("MV32 lc <- la")
            lc = la
            pc += 1
        elif memory[pc] == 0b10011010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to lc.
            if debug:
                print("MV32 lc <- lb")
            lc = lb
            pc += 1
        elif memory[pc] == 0b10011100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to lc.
            if debug:
                print("MV32 lc <- ld")
            lc = ld
            pc += 1
        elif memory[pc] == 0b10011101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to lc.
            if debug:
                print("MV32 lc <- ptr")
            lc = ptr
            pc += 1
        elif memory[pc] == 0b10011110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to lc.
            if debug:
                print("MV32 lc <- pc")
            lc = pc
            pc += 1
        elif memory[pc] == 0b10100001:  # MV32 {dest} <- {src}, Move 32-bit value, la to ld.
            if debug:
                print("MV32 ld <- la")
            ld = la
            pc += 1
        elif memory[pc] == 0b10100010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to ld.
            if debug:
                print("MV32 ld <- lb")
            ld = lb
            pc += 1
        elif memory[pc] == 0b10100011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to ld.
            if debug:
                print("MV32 ld <- lc")
            ld = lc
            pc += 1
        elif memory[pc] == 0b10100101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to ld.
            if debug:
                print("MV32 ld <- ptr")
            ld = ptr
            pc += 1
        elif memory[pc] == 0b10100110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to ld.
            if debug:
                print("MV32 ld <- pc")
            ld = pc
            pc += 1
        elif memory[pc] == 0b10101001:  # MV32 {dest} <- {src}, Move 32-bit value, la to ptr.
            if debug:
                print("MV32 ptr <- la")
            ptr = la
            pc += 1
        elif memory[pc] == 0b10101010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to ptr.
            if debug:
                print("MV32 ptr <- lb")
            ptr = lb
            pc += 1
        elif memory[pc] == 0b10101011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to ptr.
            if debug:
                print("MV32 ptr <- lc")
            ptr = lc
            pc += 1
        elif memory[pc] == 0b10101100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to ptr.
            if debug:
                print("MV32 ptr <- ld")
            ptr = ld
            pc += 1
        elif memory[pc] == 0b10101110:  # MV32 {dest} <- {src}, Move 32-bit value, pc to ptr.
            if debug:
                print("MV32 ptr <- pc")
            ptr = pc
            pc += 1
        elif memory[pc] == 0b10110001:  # MV32 {dest} <- {src}, Move 32-bit value, la to pc.
            if debug:
                print("MV32 pc <- la")
            pc = la
        elif memory[pc] == 0b10110010:  # MV32 {dest} <- {src}, Move 32-bit value, lb to pc.
            if debug:
                print("MV32 pc <- lb")
            pc = lb
        elif memory[pc] == 0b10110011:  # MV32 {dest} <- {src}, Move 32-bit value, lc to pc.
            if debug:
                print("MV32 pc <- lc")
            pc = lc
        elif memory[pc] == 0b10110100:  # MV32 {dest} <- {src}, Move 32-bit value, ld to pc.
            if debug:
                print("MV32 pc <- ld")
            pc = ld
        elif memory[pc] == 0b10110101:  # MV32 {dest} <- {src}, Move 32-bit value, ptr to pc.
            if debug:
                print("MV32 pc <- ptr")
            pc = ptr
        elif memory[pc] == 0x02:  # OUT, Output byte, value of a.
            if debug:
                print("OUT", chr(a))
            out_stream += chr(a)
            pc += 1
        elif memory[pc] == 0xC3:  # SUB a <- b, 8-bit subtraction, b from a.
            if debug:
                print("SUB", a, b)
            a -= b
            if a < 0:
                a += 256
            pc += 1
        elif memory[pc] == 0xC4:  # XOR a <- b, 8-bit bitwise exclusive OR, b XOR a.
            if debug:
                print("XOR", a, b)
            a ^= b
            pc += 1
        else:
            if debug:
                print("Invalid Instruction", memory[pc])
            pc += 1
    return out_stream
