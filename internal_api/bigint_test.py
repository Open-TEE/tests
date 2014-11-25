#!/usr/bin/env python2
# Unit tests for Arithmetical API

import cffi
from bigint_ffi import api, ffi
import unittest
import random
from fractions import gcd
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes

bits = 1024 * 92
length = api.getBigIntSizeInU32(bits)

TEE_ERROR_OVERFLOW = 0xFFFF300F

def stripbits32(value):
    neg = -1 if value < 0 else 1
    return neg * (abs(value) & 0x7FFFFFFF)

def egcd(a, b):
    u, u1 = 1, 0
    v, v1 = 0, 1
    g, g1 = a, b
    while g1:
        q = g // g1
        u, u1 = u1, u - q * u1
        v, v1 = v1, v - q * v1
        g, g1 = g1, g - q * g1
    return u, v, g

def convert_integer_to_octet(value, bigint):
    octetstring = long_to_bytes(abs(value))

    sign = 1 if value < 0 else 0
    tmp_cstring = ffi.new("uint8_t[%d]" % len(octetstring), octetstring)

    api.TEE_BigIntConvertFromOctetString(bigint, tmp_cstring, len(octetstring), sign)

def convert_octet_to_integer(bigint):
    size = len(bigint) * 2
    tmp_cstring = ffi.new("uint8_t[]", size)

    # Get the sign of bigint
    sign = -1 if api.TEE_BigIntCmpS32(bigint, 0) < 0 else 1

    if api.TEE_BigIntConvertToOctetString(tmp_cstring, size, bigint) != 0:
        raise "Short buffer"

    return sign * bytes_to_long(ffi.buffer(tmp_cstring))

class BasicArithmetic(unittest.TestCase):

    def setUp(self):
        # Allocate memory and initialize 3 bigint numbers
        self.bigint_dest = ffi.new("TEE_BigInt[]", length);
        self.bigint_dest2 = ffi.new("TEE_BigInt[]", length);
        self.bigint_a    = ffi.new("TEE_BigInt[]", length);
        self.bigint_b    = ffi.new("TEE_BigInt[]", length);
        self.bigint_n    = ffi.new("TEE_BigInt[]", length);

        api.TEE_BigIntInit(self.bigint_dest, length)
        api.TEE_BigIntInit(self.bigint_dest2, length)
        api.TEE_BigIntInit(self.bigint_a, length)
        api.TEE_BigIntInit(self.bigint_b, length)
        api.TEE_BigIntInit(self.bigint_n, length)

        self.int_dest = ffi.new("int32_t[]", 1)

    def test_arithmetic(self):
        for i in xrange(0, 1000):
            #a = random.randint(1, (2 ** bits) - 1)
            #b = random.randint(1, (2 ** bits) - 1)
            bits1 = random.randint(1, 4096)
            bits2 = random.randint(1, 4096)
            a = random.randint(1, (2 ** bits1) - 1)
            b = random.randint(1, (2 ** bits2) - 1)
            n = random.randint(1, (2 ** bits2) - 1)

            #print "a: %i b: %i n: %i" % (a, b, n)

            #api.TEE_BigIntConvertFromS32(self.bigint_a, a);
            #api.TEE_BigIntConvertFromS32(self.bigint_b, b);
            #api.TEE_BigIntConvertFromS32(self.bigint_n, n);
            #api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_a);
            #self.assertEqual(self.int_dest[0], a)
            #api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_b);
            #self.assertEqual(self.int_dest[0], b)
            #api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_n);
            #self.assertEqual(self.int_dest[0], n)

            convert_integer_to_octet(a, self.bigint_a)
            convert_integer_to_octet(b, self.bigint_b)
            convert_integer_to_octet(n, self.bigint_n)
            c = convert_octet_to_integer(self.bigint_a)
            self.assertEqual(a, c)

            # Add
            api.TEE_BigIntAdd(self.bigint_dest, self.bigint_a, self.bigint_b)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), a + b)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest);
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(a + b))

            # Sub
            api.TEE_BigIntSub(self.bigint_dest, self.bigint_a, self.bigint_b)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), a - b)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(a - b))

            # Neg
            api.TEE_BigIntNeg(self.bigint_dest, self.bigint_a)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), -a)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(-a))

            # Mul
            api.TEE_BigIntMul(self.bigint_dest, self.bigint_a, self.bigint_b)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), a * b)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(a * b))

            # Square
            api.TEE_BigIntSquare(self.bigint_dest, self.bigint_a)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), a * a)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(a*a))

            # Div
            api.TEE_BigIntDiv(self.bigint_dest, self.bigint_dest2, self.bigint_a, self.bigint_b)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), a // b)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(a // b))

            self.assertEqual(convert_octet_to_integer(self.bigint_dest2), a % b)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest2)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(a % b))

            # Mod
            api.TEE_BigIntMod(self.bigint_dest, self.bigint_a, self.bigint_n)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), a % n)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(a % n))

            # AddMod
            api.TEE_BigIntAddMod(self.bigint_dest, self.bigint_a, self.bigint_b, self.bigint_n)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), (a + b) % n)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32((a + b) % n))

            # SubMod
            api.TEE_BigIntSubMod(self.bigint_dest, self.bigint_a, self.bigint_b, self.bigint_n)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), (a - b) % n)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32((a - b) % n))

            # MulMod
            api.TEE_BigIntMulMod(self.bigint_dest, self.bigint_a, self.bigint_b, self.bigint_n)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), (a * b) % n)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32((a * b) % n))

            # SquareMod
            api.TEE_BigIntSquareMod(self.bigint_dest, self.bigint_a, self.bigint_n)
            self.assertEqual(convert_octet_to_integer(self.bigint_dest), (a * a) % n)
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32((a * a) % n))

            # InvMod
            if gcd(a,n) == 1:
                api.TEE_BigIntInvMod(self.bigint_dest, self.bigint_a, self.bigint_n)
                self.assertEqual(convert_octet_to_integer(self.bigint_dest), inverse(a, n))
                ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
                if ret != TEE_ERROR_OVERFLOW:
                    self.assertEqual(self.int_dest[0],stripbits32(inverse(a,n)))

            # RelativePrime
            ret = api.TEE_BigIntRelativePrime(self.bigint_a, self.bigint_b)
            self.assertEqual(ret == 1, gcd(a, b) == 1)

            # ComputeExtendedGcd
            egcd_val = egcd(a, b)
            api.TEE_BigIntComputeExtendedGcd(self.bigint_n, self.bigint_dest, self.bigint_dest2, self.bigint_a, self.bigint_b)

            self.assertEqual(convert_octet_to_integer(self.bigint_n), egcd_val[2])
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_n)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(egcd_val[2]))

            self.assertEqual(convert_octet_to_integer(self.bigint_dest), egcd_val[0])
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(egcd_val[0]))

            self.assertEqual(convert_octet_to_integer(self.bigint_dest2), egcd_val[1])
            ret = api.TEE_BigIntConvertToS32(self.int_dest, self.bigint_dest2)
            if ret != TEE_ERROR_OVERFLOW:
                self.assertEqual(self.int_dest[0], stripbits32(egcd_val[1]))


if __name__ == '__main__':
    print "Main"

    unittest.main()

    cffi.verifier.cleanup_tmpdir()
