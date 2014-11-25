import cffi
import os

from pycparser import parse_file, c_generator

ffi = cffi.FFI()

headerpath = "%s/../../emulator/internal_api/tee_bigint.h" % os.getcwd()
ast = parse_file(headerpath, use_cpp=True)
generator = c_generator.CGenerator()
cdef = generator.visit(ast)

# Needed for testing, Python CFFI can't "call" macros directly
cdef = "\n".join([cdef, 'size_t getBigIntSizeInU32(size_t n);'])
ffi.cdef(cdef)

internal_api_lib_path = os.path.abspath("../../gcc-debug")
api = ffi.verify("""
#include \"%s/../../emulator/internal_api/tee_bigint.h\"

size_t getBigIntSizeInU32(size_t n)
{
    return TEE_BigIntSizeInU32(n);
}
""" % (os.getcwd()),
library_dirs = [internal_api_lib_path],
libraries = ['InternalApi'])
