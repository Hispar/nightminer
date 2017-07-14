import hashlib
import hmac
import struct

from nightminer.constants import SCRYPT_LIBRARY_AUTO, SCRYPT_LIBRARY_LTC, SCRYPT_LIBRARY_SCRYPT, SCRYPT_LIBRARY_PYTHON

SCRYPT_LIBRARY = None
scrypt_proof_of_work = None


def set_scrypt_library(library=SCRYPT_LIBRARY_AUTO):
    """Sets the scrypt library implementation to use."""

    global SCRYPT_LIBRARY
    global scrypt_proof_of_work

    if library == SCRYPT_LIBRARY_LTC:
        import ltc_scrypt
        scrypt_proof_of_work = ltc_scrypt.getPoWHash
        SCRYPT_LIBRARY = library

    elif library == SCRYPT_LIBRARY_SCRYPT:
        import scrypt as NativeScrypt
        scrypt_proof_of_work = lambda header: NativeScrypt.hash(header, header, 1024, 1, 1, 32)
        SCRYPT_LIBRARY = library

    # Try to load a faster version of scrypt before using the pure-Python implementation
    elif library == SCRYPT_LIBRARY_AUTO:
        try:
            set_scrypt_library(SCRYPT_LIBRARY_LTC)
        except Exception as e:
            try:
                set_scrypt_library(SCRYPT_LIBRARY_SCRYPT)
            except Exception as e:
                set_scrypt_library(SCRYPT_LIBRARY_PYTHON)
    else:
        scrypt_proof_of_work = lambda header: scrypt(header, header, 1024, 1, 1, 32)
        SCRYPT_LIBRARY = library


def scrypt(password, salt, N, r, p, dkLen):
    """Returns the result of the scrypt password-based key derivation function.

       This is used as the foundation of the proof-of-work for litecoin and other
       scrypt-based coins, using the parameters:
         password = bloack_header
         salt     = block_header
         N        = 1024
         r        = 1
         p        = 1
         dkLen    = 256 bits (=32 bytes)

       Please note, that this is a pure Python implementation, and is slow. VERY
       slow. It is meant only for completeness of a pure-Python, one file stratum
       server for Litecoin.

       I have included the ltc_scrypt C-binding from p2pool (https://github.com/forrestv/p2pool)
       which is several thousand times faster. The server will automatically attempt to load
       the faster module (use set_scrypt_library to choose a specific library).
     """

    def array_overwrite(source, source_start, dest, dest_start, length):
        """Overwrites the dest array with the source array."""

        for i in range(0, length):
            dest[dest_start + i] = source[source_start + i]

    def blockxor(source, source_start, dest, dest_start, length):
        """Performs xor on arrays source and dest, storing the result back in dest."""

        for i in range(0, length):
            dest[dest_start + i] = chr(ord(dest[dest_start + i]) ^ ord(source[source_start + i]))

    def pbkdf2(passphrase, salt, count, dkLen, prf):
        """Returns the result of the Password-Based Key Derivation Function 2.

           See http://en.wikipedia.org/wiki/PBKDF2
        """

        def f(block_number):
            """The function "f"."""
            U = prf(passphrase, str(salt + str(struct.pack('>L', block_number))).encode('utf-8'))

            # Not used for scrpyt-based coins, could be removed, but part of a more general solution
            if count > 1:
                U = [c for c in U]
                for i in range(2, 1 + count):
                    blockxor(prf(passphrase, ''.join(U)), 0, U, 0, len(U))
                U = ''.join(U)

            return str(U)

        # PBKDF2 implementation
        size = 0

        block_number = 0
        blocks = []

        # The iterations
        while size < dkLen:
            block_number += 1
            block = f(block_number)

            blocks.append(block)
            size += len(block)

        return ''.join(blocks)[:dkLen]

    def integerify(B, Bi, r):
        """"A bijective function from ({0, 1} ** k) to {0, ..., (2 ** k) - 1"."""

        Bi += (2 * r - 1) * 64
        n = ord(B[Bi]) | (ord(B[Bi + 1]) << 8) | (ord(B[Bi + 2]) << 16) | (ord(B[Bi + 3]) << 24)
        return n

    def make_int32(v):
        """Converts (truncates, two's compliments) a number to an int32."""

        if v > 0x7fffffff: return -1 * ((~v & 0xffffffff) + 1)
        return v

    def R(X, destination, a1, a2, b):
        """A single round of Salsa."""

        a = (X[a1] + X[a2]) & 0xffffffff
        X[destination] ^= ((a << b) | (a >> (32 - b)))

    def salsa20_8(B):
        """Salsa 20/8 stream cypher; Used by BlockMix. See http://en.wikipedia.org/wiki/Salsa20"""

        # Convert the character array into an int32 array
        B32 = [make_int32(
            (ord(B[i * 4]) | (ord(B[i * 4 + 1]) << 8) | (ord(B[i * 4 + 2]) << 16) | (ord(B[i * 4 + 3]) << 24))) for i in
            range(0, 16)]
        x = [i for i in B32]

        # Salsa... Time to dance.
        for i in range(8, 0, -2):
            R(x, 4, 0, 12, 7);
            R(x, 8, 4, 0, 9);
            R(x, 12, 8, 4, 13);
            R(x, 0, 12, 8, 18)
            R(x, 9, 5, 1, 7);
            R(x, 13, 9, 5, 9);
            R(x, 1, 13, 9, 13);
            R(x, 5, 1, 13, 18)
            R(x, 14, 10, 6, 7);
            R(x, 2, 14, 10, 9);
            R(x, 6, 2, 14, 13);
            R(x, 10, 6, 2, 18)
            R(x, 3, 15, 11, 7);
            R(x, 7, 3, 15, 9);
            R(x, 11, 7, 3, 13);
            R(x, 15, 11, 7, 18)
            R(x, 1, 0, 3, 7);
            R(x, 2, 1, 0, 9);
            R(x, 3, 2, 1, 13);
            R(x, 0, 3, 2, 18)
            R(x, 6, 5, 4, 7);
            R(x, 7, 6, 5, 9);
            R(x, 4, 7, 6, 13);
            R(x, 5, 4, 7, 18)
            R(x, 11, 10, 9, 7);
            R(x, 8, 11, 10, 9);
            R(x, 9, 8, 11, 13);
            R(x, 10, 9, 8, 18)
            R(x, 12, 15, 14, 7);
            R(x, 13, 12, 15, 9);
            R(x, 14, 13, 12, 13);
            R(x, 15, 14, 13, 18)

        # Coerce into nice happy 32-bit integers
        B32 = [make_int32(x[i] + B32[i]) for i in range(0, 16)]

        # Convert back to bytes
        for i in range(0, 16):
            B[i * 4 + 0] = chr((B32[i] >> 0) & 0xff)
            B[i * 4 + 1] = chr((B32[i] >> 8) & 0xff)
            B[i * 4 + 2] = chr((B32[i] >> 16) & 0xff)
            B[i * 4 + 3] = chr((B32[i] >> 24) & 0xff)

    def blockmix_salsa8(BY, Bi, Yi, r):
        """Blockmix; Used by SMix."""

        start = Bi + (2 * r - 1) * 64
        X = [BY[i] for i in range(start, start + 64)]  # BlockMix - 1

        for i in range(0, 2 * r):  # BlockMix - 2
            blockxor(BY, i * 64, X, 0, 64)  # BlockMix - 3(inner)
            salsa20_8(X)  # BlockMix - 3(outer)
            array_overwrite(X, 0, BY, Yi + (i * 64), 64)  # BlockMix - 4

        for i in range(0, r):  # BlockMix - 6 (and below)
            array_overwrite(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64)

        for i in range(0, r):
            array_overwrite(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64)

    def smix(B, Bi, r, N, V, X):
        """SMix; a specific case of ROMix. See scrypt.pdf in the links above."""

        array_overwrite(B, Bi, X, 0, 128 * r)  # ROMix - 1

        for i in range(0, N):  # ROMix - 2
            array_overwrite(X, 0, V, i * (128 * r), 128 * r)  # ROMix - 3
            blockmix_salsa8(X, 0, 128 * r, r)  # ROMix - 4

        for i in range(0, N):  # ROMix - 6
            j = integerify(X, 0, r) & (N - 1)  # ROMix - 7
            blockxor(V, j * (128 * r), X, 0, 128 * r)  # ROMix - 8(inner)
            blockmix_salsa8(X, 0, 128 * r, r)  # ROMix - 9(outer)

        array_overwrite(X, 0, B, Bi, 128 * r)  # ROMix - 10

    # Scrypt implementation. Significant thanks to https://github.com/wg/scrypt
    if N < 2 or (N & (N - 1)): raise ValueError('Scrypt N must be a power of 2 greater than 1')

    prf = lambda k, m: hmac.new(key=k.encode('utf-8'), msg=m, digestmod=hashlib.sha256).digest()

    # pw_bytes = pw.encode('utf-8')
    # salt_bytes = salt.encode('utf-8')
    # return hashlib.sha256(pw_bytes + salt_bytes).hexdigest() + "," + salt

    DK = [chr(0)] * dkLen

    B = [c for c in pbkdf2(password, salt, 1, p * 128 * r, prf)]
    XY = [chr(0)] * (256 * r)
    V = [chr(0)] * (128 * r * N)

    for i in range(0, p):
        smix(B, i * 128 * r, r, N, V, XY)

    return pbkdf2(password, ''.join(B), 1, dkLen, prf)
