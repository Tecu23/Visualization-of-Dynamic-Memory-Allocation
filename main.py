from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
  
  # code to be emulated
X86_CODE64 = b"\x55\x48\x89\xE5\x48\x83\xEC\x20\x89\x7D\xEC\x48\x89\x75\xE0\xBF\x0A\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x89\x45\xF8\x48\x8B\x45\xF8\x48\x89\xC7\xE8\x00\x00\x00\x00\xBF\x05\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x89\x45\xF0\xB8\x00\x00\x00\x00"
a = b"\xE8\xFC\xFF\xFF\xFF\xE8\xFC\xFF\xFF\xFF" # INC ecx; DEC edx
  
  # heap memory list
memory_list = {}

  # memory address for the code
CODE_ADDRESS = 0x400000
SIZE_MB = 1024 * 1024

  # memory address for stack and heap
STACK_ADDRESS = 0x0
STACK_SIZE = 4 * SIZE_MB

HEAP_ADDRESS = 0x600000
HEAP_SIZE = 5 * SIZE_MB


def hook_code(mu, address, size, user_data):
  print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 
  #if size == 0x5:
    #mu.reg_write(UC_X86_REG_EIP,address+size) 

print("Emulate i386 code")
try:
    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    # map 2MB memory for this emulation
    mu.mem_map(CODE_ADDRESS, 2 * SIZE_MB)
    mu.mem_map(STACK_ADDRESS, STACK_SIZE)
    mu.mem_map(HEAP_ADDRESS, HEAP_SIZE)

    # write machine code to be emulated to memory
    mu.mem_write(CODE_ADDRESS, X86_CODE64)

    # setting the base pointer to the stack
    mu.reg_write(UC_X86_REG_RBP, STACK_ADDRESS + STACK_SIZE - 1)
    mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 1)

    # initialize machine registers
    mu.reg_write(UC_X86_REG_RCX, 0x1234)
    mu.reg_write(UC_X86_REG_RDX, 0x7890)

    mu.hook_add(UC_HOOK_CODE, hook_code)

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(X86_CODE64))

    # now print out some registers
    print("Emulation done. Below is the CPU context")

    r_rcx = mu.reg_read(UC_X86_REG_RCX)
    r_rdx = mu.reg_read(UC_X86_REG_RDX)
    r_rip = mu.reg_read(UC_X86_REG_RIP)
    print(">>> ECX = 0x%x" %r_rcx)
    print(">>> EDX = 0x%x" %r_rdx)
    print(">>> EIP = 0x%x" %r_rip)

except UcError as e:
    print("ERROR: %s" % e)

    