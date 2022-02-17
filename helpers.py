######################################################
# helpers.py
#
# Needed for onion.py
#
# Implements various helper functions needed for
# the Tom's Data Onion programming challenge.
#
# Created by: Arlen McDonald
#
# 12/20/21
######################################################
import base64
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, _unwrap_core


def decode_85(pl):
    """Decode using Adobe85, strip out whitespace, line-feeds, and control characters.

    Every layer needs this as a pre-process."""
    pl = trim(pl)
    # I am probably filtering a lot more than I need to, but it doesn't seem to hurt anything...
    return base64.a85decode(pl, adobe=True, foldspaces=False, ignorechars=b' \n\r\t\v\\s\0')


def trim(pl):
    """Trim down to the payload, delimited by <~ and ~>, adobe version."""
    pl = pl[pl.index("ayload ]"):]  # Drop the header first, could contain stray markers...
    pl = pl[pl.index("<~"):pl.rindex("~>") + 2]
    pl = pl.replace("z", "!!!!!")  # Part of the spec, but not sure if it is needed...
    pad(pl)
    return pl


def pad(pl):
    """Pad the string with u, so they are even groups of five."""
    pl = pl[:pl.index("~>")]
    if len(pl) - 2 % 5 == 1:
        pl += "uuuu"
    elif len(pl) - 2 % 5 == 2:
        pl += "uuu"
    elif len(pl) - 2 % 5 == 3:
        pl += "uu"
    elif len(pl) - 2 % 5 == 4:
        pl += "u"
    return pl + "~>"


def writeF(pl, fn):
    """Write results to a file."""
    with open(fn, "w") as w_fl:
        w_fl.write(pl)
    w_fl.close()


def parity_test(byt):
    """Test parity bit of a byte vs actual parity, return boolean."""
    pty = byt & 1
    byt >>= 1
    if parity(byt) == pty:
        return True
    return False


def parity(byt):
    """Determine parity of a byte, return 0 for even, 1 for odd."""
    # Found at: https://stackoverflow.com/questions/57548852/checking-parity-of-a-number-in-python
    pty = 0
    while byt:
        pty ^= byt & 1
        byt >>= 1
    return pty


def byte_str(tb: bytes):
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


def src_ip_test(pkt, a, b, c, d):
    """Determine if source IP address matches input."""
    if pkt[12] == a and pkt[13] == b and pkt[14] == c and pkt[15] == d:
        return True
    return False


def dest_ip_test(pkt, a, b, c, d):
    """Determine if destination IP address matches input."""
    if pkt[16] == a and pkt[17] == b and pkt[18] == c and pkt[19] == d:
        return True
    return False


def get_dest_port(pkt):
    """Return destination port of input packet."""
    port = int.from_bytes(pkt[22:24], byteorder="big", signed=False)
    return port


def ip_hdr_cs(pkt):
    """Test if IPv4 header checksum is valid."""
    tot = 0
    for x in range(0, 19, 2):
        tot += int.from_bytes(pkt[x:x + 2], byteorder="big", signed=False)
    if ones_comp_16(tot) == 0:  # One's complement of total should equal 0.
        return True
    return False


def udp_hdr_cs(pkt):
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
    if ones_comp_16(tot) == 0:
        return True
    return False


def ones_comp_16(n):
    """One's Complement of a number, 16 bit words only."""
    return ~n & 0xffff  # Invert then and to get rid of the sign bit.


def key_unwrap(wrapping_key, wrapping_iv, wrapped_key):
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
    a, r = _unwrap_core(wrapping_key, a, r)
    if bytes_eq(a, bytes(wrapping_iv)) is False:
        raise InvalidUnwrap()

    return b"".join(r)
