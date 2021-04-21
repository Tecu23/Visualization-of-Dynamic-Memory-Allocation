from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
  
  # code to be emulated
X86_CODE32 = b"\x41\x4a\xE8\xFC\xFF\xFF\xFF\xE8\xFC\xFF\xFF\xFF\xE8\xFC\xFF\xFF\xFF" # INC ecx; DEC edx
  
  # memory address where emulation starts
ADDRESS = 0x1000000

def hook_code(mu, address, size, user_data):
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 
    if size == 0x5:
        mu.reg_write(UC_X86_REG_EIP,address+size) 

print("Emulate i386 code")
try:
    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024)

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, X86_CODE32)

    # initialize machine registers
    mu.reg_write(UC_X86_REG_ECX, 0x1234)
    mu.reg_write(UC_X86_REG_EDX, 0x7890)

    mu.hook_add(UC_HOOK_CODE, hook_code)

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

    # now print out some registers
    print("Emulation done. Below is the CPU context")

    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    r_rip = mu.reg_read(UC_X86_REG_EIP)
    print(">>> ECX = 0x%x" %r_ecx)
    print(">>> EDX = 0x%x" %r_edx)
    print(">>> EIP = 0x%x" %r_rip)

except UcError as e:
    print("ERROR: %s" % e)