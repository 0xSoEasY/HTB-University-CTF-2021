# The vault

## First contact with the challenge

Fist of all, let’s gather some information on the binary.

```bash
$ file ./vault
./vault: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, stripped
```

So we have got an x86_64 ELF binary, stripped (not cool). Let's try to run it to see if we've got something interesting.

```bash
$ ./vault 
Could not find credentials

$ ./vault 1234 5678
Could not find credentials
```

We've got a message saying that the program could not find credentials, even with parameters. Let's use strace to see if he's not looking for a file or something.

```bash
$ strace ./vault 
execve("./vault", ["./vault"], 0x7ffd0bf9b380 /* 58 vars */) = 0
brk(NULL)                               = 0x55d9c15af000
[...]
mprotect(0x55d9c069a000, 16384, PROT_READ) = 0
mprotect(0x7f967c4da000, 4096, PROT_READ) = 0
munmap(0x7f967c4bb000, 125441)          = 0
brk(NULL)                               = 0x55d9c15af000
brk(0x55d9c15d0000)                     = 0x55d9c15d0000
openat(AT_FDCWD, "flag.txt", O_RDONLY)  = -1 ENOENT (No such file or directory)
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
write(1, "Could not find credentials\n", 27Could not find credentials
) = 27
exit_group(-1)                          = ?
+++ exited with 255 +++
``` 

We can see that the program is trying to open a file named "flag.txt". Let's create one with a garbage flag and retry.

```bash
$ echo "HTB{THIS_IS_A_FAKE_FLAG}" > flag.txt
$ ./vault 
Incorrect Credentials - Anti Intruder Sequence Activated...
```

Everything seems to be working fine, now let's open this challenge in IDA.

## Reverse engineering

To win some time I've already renamed some variables. Here is the decompilation's result of the important part of the main function:

```c
  std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream(input_stream, "flag.txt", 8LL);

  if ( (std::basic_ifstream<char,std::char_traits<char>>::is_open(input_stream) & 1) == 0 ) { 
    std::operator<<<std::char_traits<char>>(&std::cout, "Could not find credentials\n");
    exit(-1);
  }

  valid_flag = 1;
  for ( i = 0; ; ++i ) {
  
    v4 = 0;
    if ( i < 25 )
      v4 = std::basic_ios<char,std::char_traits<char>>::good(input_stream + *(input_stream[0] - 24));

    if ( (v4 & 1) == 0 )
      break;

    std::istream::get(input_stream, &input_char);
    flag_char_function = functions_vtable[BUFFER_INDEXES[i]];

    flag_char = (**flag_char_function)(flag_char_function);

    if ( input_char != flag_char )
      valid_flag = 0;
  }

  if ( (valid_flag & 1) != 0 ) {
    result = "Credentials Accepted! Vault Unlocking...\n";
    std::operator<<<std::char_traits<char>>(&std::cout, "Credentials Accepted! Vault Unlocking...\n");
  
  }else{
    result = "Incorrect Credentials - Anti Intruder Sequence Activated...\n";
    std::operator<<<std::char_traits<char>>(&std::cout, "Incorrect Credentials - Anti Intruder Sequence Activated...\n");
  }
```

We can resume this function in C-like pseudo code like this: 

```c
int valid = 1;

for(int i=0; i < 25; i++){
    int64 function = functions_vtable[BUFFER_INDEXES[i]];
    
    if(user_input[i] != function())
        valid = 0;
}

if(valid)
    puts("Credentials Accepted! Vault Unlocking...");
else
    puts("Incorrect Credentials - Anti Intruder Sequence Activated...");
```

We can notice that even if our flag is not the correct one, the program will not break and will continue comparing all the characters of our input to the characters of the flag.

## Flag via debug or scripting

The easiest way to flag this challenge is to set a breakpoint at the cmp instruction that will compare our input char and the real flag char (note those addresses will change at every execution because it's a PIE).

```x86asm
0xC353:            movsxd  rcx, [rbp+var_22C]
0xC35A:            lea     rsi, unk_E090
0xC361:            movzx   ecx, byte ptr [rcx+rsi]
0xC365:            mov     esi, ecx
0xC367:            lea     rcx, off_17880
0xC36E:            mov     rdi, [rcx+rsi*8]
0xC372:            mov     rcx, [rdi]
0xC375:            mov     rcx, [rcx]
0xC378:            call    rcx
0xC37A:            mov     cl, al
0xC37C:            mov     [rbp+var_23B], cl
0xC382:            jmp     $+5

0xC387: loc_C387: 
0xC387:            mov     al, [rbp+var_23B]
0xC38D:            mov     [rbp+var_22D], al
0xC393:            movsx   eax, [rbp+var_211]
0xC39A:            movzx   ecx, [rbp+var_22D]
0xC3A1:            cmp     eax, ecx
0xC3A3:            jz      loc_C3B0
0xC3A9:            mov     [rbp+var_225], 0

0xC3B0: loc_C3B0: 
0xC3B0:            mov     eax, [rbp+var_22C]
0xC3B6:            add     eax, 1
0xC3B9:            mov     [rbp+var_22C], eax
```

Before, we have to make sure to have a local flag of 25 chars: we can put `HTB{AAAAAAAAAAAAAAAAAAAA}` in `flag.txt`.

We will then put our breakpoint at `0xC3A1: cmp eax, ecx` in gdb or IDA for example.
At each round, the value of our input will be in `eax` and the corresponding char of the flag will be in `ecx`: we will note the `ecx` value, pass to the next char, note the `ecx` value, pass to the next char etc... Or we can automate this process with a script, using Qiling for example!

```python
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
```
We can then execute it:
```bash
$ python3 solve_vault.py 
Incorrect Credentials - Anti Intruder Sequence Activated...
[+] FLAG: HTB{vt4bl3s_4r3_c00l_huh}
```

And we've got the flag `HTB{vt4bl3s_4r3_c00l_huh}` wich we can try on the challenge: 

```bash
$ echo "HTB{vt4bl3s_4r3_c00l_huh}" > flag.txt
$ ./vault
Credentials Accepted! Vault Unlocking...
```

We can then validate the challenge with this flag!