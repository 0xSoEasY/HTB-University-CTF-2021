from qiling import *
from qiling.os.mapper import QlFsMappedObject

class flag_file(QlFsMappedObject):
    def read(self, size):
        return b"HTB{AAAAAAAAAAAAAAAAAAAA}"

    def fstat(self):
        return -1

    def close(self):
        return 0

def print_ecx(ql):
    """
    This function will be called every time our hook_address will be reached
    """
    print(chr(ql.reg.ecx), end='')

if __name__ == "__main__":
    ql = Qiling(["vault"], rootfs="./rootfs/x8664_linux", console=False)
    ql.add_fs_mapper('flag.txt', flag_file())
    ql.hook_address(print_ecx, ql.loader.load_address + 0xc3a1) # PIE binary

    print("[+] FLAG: ", end='')
    ql.run()