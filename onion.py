#####################################################################
# Onion.py
#
# This is a programing challenge which turned out to be a lot of fun!
# Thanks to Tom Dalling for providing it!
#
# Created to improve my Python skills.
# Also trying out the PyCharm IDE.
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
# First fully working version! 5/12/21
# Moved functions to a separate file 12/20/21
#
#####################################################################
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from helpers import decode_85, writeF, parity_test, byte_str, packetize, depacketize, \
    src_ip_test, dest_ip_test, get_dest_port, ip_hdr_cs, udp_hdr_cs, key_unwrap
from tomtel import tomtel_VM


# Main - Initialize
with open("onion.txt") as r_fl:  # Read only
    in_f = r_fl.read()
r_fl.close()


# Layer 0 - ASCII85
payL = decode_85(in_f)
writeF(payL.decode("utf-8"), "onion1.txt")


# Layer 1 - Bitwise Operations
ba = bytearray(decode_85(payL.decode("utf-8")))  # Need bytes for bit manipulation.
for i in range(len(ba)):
    ba[i] ^= 0b01010101  # XOR to flip every other bit, 01010101 = 85.
    ba[i] >>= 1  # Right shift one bit.
payL = ba.decode("utf-8")
writeF(payL, "onion2.txt")


# Layer 2 - Parity Bit
ba = bytearray(decode_85(payL))

# Test for bad parity and discard fails
ba2 = bytearray()
for i in ba:
    if parity_test(i):
        ba2.append(i)

# Convert from 8, 7 bit groups to 7, 8 bit groups.  Uses a string of text 1s and 0s as an intermediary step.
ba = bytearray()
for i in range(0, len(ba2), 8):
    r_str = byte_str(ba2[i]) + byte_str(ba2[i + 1]) \
            + byte_str(ba2[i + 2]) + byte_str(ba2[i + 3]) \
            + byte_str(ba2[i + 4]) + byte_str(ba2[i + 5]) \
            + byte_str(ba2[i + 6]) + byte_str(ba2[i + 7])  # Bytes to string.
    ba += bytearray(int(r_str, 2).to_bytes(7, byteorder="big", signed=False))  # String to bytes.
payL = ba.decode("utf-8")
writeF(payL, "onion3.txt")


# Layer 3 - XOR Encryption
ba = bytearray(decode_85(payL))
key = bytearray(b'\x6c\x24\x84\x8e\x42\x19\xa8\xe1'
                b'\xc5\xdb\x57\x65\xb9\xc6\x14\x9e'
                b'\xa5\x19\x35\x96\x3b\x39\x7f\xa5'
                b'\x65\xd1\xfe\x01\x85\x7d\xd9\x4c')  # 32 Byte key, manually derived it.

for i in range(len(ba)):
    ba[i] ^= key[i % 32]  # XOR bytearray with key, 32 byte chunks.
payL = ba.decode("utf-8")
writeF(payL, "onion4.txt")


# Layer 4 - Network Traffic
ba = bytearray(decode_85(payL))
packets = packetize(ba)  # Break up into packets

# Filter out bad packets
testing = 0
while testing < len(packets):
    if src_ip_test(packets[testing], 10, 1, 1, 10) is False \
            or dest_ip_test(packets[testing], 10, 1, 1, 200) is False \
            or get_dest_port(packets[testing]) != 42069 \
            or ip_hdr_cs(packets[testing]) is False \
            or udp_hdr_cs(packets[testing]) is False:
        packets.pop(testing)
    else:
        testing += 1
payL = depacketize(packets)  # Strip out payload data
writeF(payL, "onion5.txt")


# layer 5 - Advanced Encryption Standard
ba = bytearray(decode_85(payL))
kEK = ba[0:32]  # Key Encrypting Key
kIV = ba[32:40]  # Key Initialization Vector
eKey = ba[40:80]  # Encrypted key
pIV = ba[80:96]  # Payload Initialization Vector
ePayL = ba[96:]  # Encrypted payload
dKey = key_unwrap(wrapping_key=kEK, wrapping_iv=kIV, wrapped_key=eKey, backend=default_backend())
c_text = Cipher(algorithms.AES(dKey), modes.CTR(pIV), backend=default_backend())
payL = c_text.decryptor().update(ePayL).decode("utf-8")
writeF(payL, "onion6.txt")


# Layer 6 - Virtual Machine
# Replace ba with hello to run test program, set debug to true to monitor execution.
hello = bytearray(b'\x50\x48\xC2\x02\xA8\x4D\x00\x00\x00\x4F\x02\x50\x09\xC4\x02\x02'
                  b'\xE1\x01\x4F\x02\xC1\x22\x1D\x00\x00\x00\x48\x30\x02\x58\x03\x4F'
                  b'\x02\xB0\x29\x00\x00\x00\x48\x31\x02\x50\x0C\xC3\x02\xAA\x57\x48'
                  b'\x02\xC1\x21\x3A\x00\x00\x00\x48\x32\x02\x48\x77\x02\x48\x6F\x02'
                  b'\x48\x72\x02\x48\x6C\x02\x48\x64\x02\x48\x21\x02\x01\x65\x6F\x33'
                  b'\x34\x2C')  # Test program, prints Hello World!
ba = bytearray(decode_85(payL))
# ba = hello
payL = tomtel_VM(ba, debug=False)

# The Core - Shocking Results!
print(payL)
# writeF(payL, "core.txt")

# Exit
