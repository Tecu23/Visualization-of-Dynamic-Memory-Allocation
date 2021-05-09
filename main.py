from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from heap import Heap
  
# code to be emulated
X86_CODE64 = b"\x48\x89\xe5\xbf\xa0\x86\x01\x00\xe8\x24\x00\x00\x00\x48\x89\x45\xf8\xbf\x40\x0d\x03\x00\xe8\x16\x00\x00\x00\x48\x89\x45\xf0\xbf\xe0\x93\x04\x00\xe8\x08\x00\x00\x00\x48\x89\x45\xe8\xbf\x80\x1a\x06\x00\xe8\xfa\xff\xff\xff\x48\x89\x45\xe0\x48\x8b\x45\xe0\x48\x89\xc7\xe8\xdc\xff\xff\xff\x48\x89\x45\xe0\xbf\xa0\x0f\x00\x00\xe8\xdc\xff\xff\xff\x48\x89\x45\xd8\x48\x8b\x45\xf8\x48\x8b\x5d\xf0\x48\x8b\x4d\xe8\x48\x8b\x55\xe0\x4c\x8b\x55\xd8"

# memory address for the code
CODE_ADDRESS = 0x400000
SIZE_MB = 1024 * 1024

# memory address for stack and heap
STACK_ADDRESS = 0x0
STACK_SIZE = 4 * SIZE_MB

# heap constant
HEAP_ADDRESS = 0x600000
HEAP_SIZE = SIZE_MB


# malloc() instructions addresses
MALLOC_ADDRESSES = [0x400008, 0x400016, 0x400024, 0x400032, 0x400050]

# free() instructions addresses
FREE_ADDRESSES = [0x400042]

def hook_code(mu, address, size, user_data):
  print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

  if address in MALLOC_ADDRESSES:

    print("THIS IS A MALLOC CALL")
    # skipping the instruction
    mu.reg_write(UC_X86_REG_RIP,address+size)
    
    # keeping the size of the allocation of memory and returning the allocated address
    malloc_size = mu.reg_read(UC_X86_REG_EDI)

    allocated_address = h.allocate(malloc_size) 

    # now we check if we allocated the memory
    if allocated_address == None:
      print("We don't have enough space in the heap to alocate this space, 0 was placed in RAX")
      mu.reg_write(UC_X86_REG_RAX,0)
    else:
      # now putting that allocated address in rax, mirroring a call to malloc
      mu.reg_write(UC_X86_REG_RAX,allocated_address)

    h.print()

  if address in FREE_ADDRESSES:

    print("This is a FREE CALL")
    # skipping the instruction
    mu.reg_write(UC_X86_REG_RIP,address+size)

    # keeping the address of the deallocation
    free_address = mu.reg_read(UC_X86_REG_RDI)

    # now we call the deallocator function in the heap
    new_address = h.deallocate(free_address)

    # if the new address is not 0 then we have a problem
    if new_address != 0:
      print("Deallocation was unsuccessfull. Something went wrong")
    else:
      # else we put 0 in RAX to be put in the stack
      mu.reg_write(UC_X86_REG_RAX,new_address)

    h.print()

    

print("Emulate i386 code")
try:
  # Initialize emulator in X86-32bit mode
  mu = Uc(UC_ARCH_X86, UC_MODE_64)

  # map 2MB memory for the code to be emulated and 4MB to the stack
  mu.mem_map(CODE_ADDRESS, 2 * SIZE_MB)
  mu.mem_map(STACK_ADDRESS, STACK_SIZE)

  # created the heap memory with that address and size
  h = Heap(HEAP_ADDRESS,HEAP_SIZE)

  # write machine code to be emulated to memory
  mu.mem_write(CODE_ADDRESS, X86_CODE64)

  # setting the base pointer to the stack
  mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 1)

  mu.hook_add(UC_HOOK_CODE, hook_code)

  # emulate code in infinite time & unlimited instructions
  mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(X86_CODE64))

  print("Emulation done. Below is the CPU context")

  r_rsp = mu.reg_read(UC_X86_REG_RSP)
  r_rax = mu.reg_read(UC_X86_REG_RAX)
  r_rbx = mu.reg_read(UC_X86_REG_RBX)
  r_rcx = mu.reg_read(UC_X86_REG_RCX)
  r_rdx = mu.reg_read(UC_X86_REG_RDX)
  r_10  = mu.reg_read(UC_X86_REG_R10)

    
  print(">>> RSP = 0x%x" %r_rsp)
  print(">>> RAX = 0x%x" %r_rax)
  print(">>> RBX = 0x%x" %r_rbx)
  print(">>> RCX = 0x%x" %r_rcx)
  print(">>> RDX = 0x%x" %r_rdx)
  print(">>> R10 = 0x%x" %r_10)

except UcError as e:
  print("ERROR: %s" % e)

    