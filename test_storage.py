from subprocess import check_call

def test_storage():
    check_call('gcc-debug/crypto_test')
