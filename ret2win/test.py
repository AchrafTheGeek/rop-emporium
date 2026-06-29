from pwn import *

context.terminal = ['st', '--', 'sh', '-c']

p = process('./ret2win')
gdb.attach(p, gdbscript='source ~/usr/share/pwndbg/gdbinit.py')
pause()

print(p.recv().decode())
p.sendline(b"hi")
print(p.recv().decode())

p.interactive()
