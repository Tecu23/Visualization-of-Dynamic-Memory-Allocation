from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from functions import *
  
# code to be emulated
X86_CODE64 = b"\x48\x89\xE5\x48\xC7\xC0\x04\x00\x00\x00\x48\x89\x45\xF8\x48\xC7\xC0\x05\x00\x00\x00\x48\x89\x45\xF0\xBF\x06\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x89\x45\xE8\x48\x8B\x45\xF8\x48\x8B\x5D\xF0\x48\x8B\x4D\xE8"

# memory address for the code
CODE_ADDRESS = 0x400000
SIZE_MB = 1024 * 1024

# memory address for stack and heap
STACK_ADDRESS = 0x0
STACK_SIZE = 4 * SIZE_MB

# heap constants
HEAP_ADDRESS = 0x600000
HEAP_SIZE = 5 * SIZE_MB
  
# heap memory list
freed_memory_list = {}
memory_list = {}
heap_pointer = HEAP_ADDRESS + HEAP_SIZE - 1;

# malloc() instructions addresses
MALLOC_ADDRESSES = [ 0x40001e ]

# free() instructions addresses
FREE_ADDRESSES = []

def hook_code(mu, address, size, user_data):
  print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

  if address in MALLOC_ADDRESSES:
    # skipping the instruction
    mu.reg_write(UC_X86_REG_RIP,address+size)
    
    # keeping the size of the allocation of memory and returning the allocated address
    malloc_size = mu.reg_read(UC_X86_REG_EDI)

    allocated_address = allocate(heap_pointer,malloc_size,memory_list) 

    # now we check if we allocated the memory
    if allocated_address == None:
      print("We don't have enough space in the heap to alocate this space, 0 was placed in RAX")
      mu.reg_write(UC_X86_REG_RAX,0)
    else:
      # now putting that allocated address in rax, mirroring a call to malloc
      mu.reg_write(UC_X86_REG_RAX,allocated_address)
    

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
  #mu.reg_write(UC_X86_REG_RBP, STACK_ADDRESS + STACK_SIZE - 1)
  mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 1)

  mu.hook_add(UC_HOOK_CODE, hook_code)

  # emulate code in infinite time & unlimited instructions
  mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(X86_CODE64))

  print("Emulation done. Below is the CPU context")

  r_rsp = mu.reg_read(UC_X86_REG_RSP)
  r_rax = mu.reg_read(UC_X86_REG_RAX)
  r_rbx = mu.reg_read(UC_X86_REG_RBX)
  r_rcx = mu.reg_read(UC_X86_REG_RCX)
    
  print(">>> RSP = 0x%x" %r_rsp)
  print(">>> RAX = 0x%x" %r_rax)
  print(">>> RBX = 0x%x" %r_rbx)
  print(">>> RCX = 0x%x" %r_rcx)

except UcError as e:
  print("ERROR: %s" % e)

    