from pwn import *
import os

os.environ["SHELL"] = "/bin/sh"

context.binary = elf = ELF("./callme")
context.arch = "amd64"
context.os = "linux"
context.terminal = ['st', '--', '/bin/sh', '-c']
