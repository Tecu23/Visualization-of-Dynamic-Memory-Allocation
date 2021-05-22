from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from heap import Heap
from constants import *
import time
import arcade

class Emulation(arcade.Window):
    """ Main application class. """

    # created the heap memory with that address and size
    h = Heap(HEAP_ADDRESS,HEAP_SIZE)

    # constructor for the emulation
    def __init__(self, width, height):
        
        super().__init__(width, height)
        arcade.set_background_color((42,43,45))

    def on_draw(self):
        """ Render the screen. """
        
        self.update_logic(self.h.HEAP_SIZE, self.h.memory_list, self.h.freed_memory_list, "", 0)
    

    def update(self, delta_time):

        """ All the logic to allocate/deallocate the memory with the unicorn engine, and the game logic goes here """

        def hook_code(mu, address, size, user_data):

            print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 
            
            # when the first instruction is called, we call the function to initialize the image on the screen
            if address == 0x400000:
                self.update_logic(self.h.HEAP_SIZE, self.h.memory_list, self.h.freed_memory_list, " ", 0)

            if address in MALLOC_ADDRESSES:
                # skipping the instruction
                mu.reg_write(UC_X86_REG_RIP,address+size)
                
                # keeping the size of the allocation of memory and returning the allocated address
                malloc_size = mu.reg_read(UC_X86_REG_EDI)

                allocated_address = self.h.allocate(malloc_size) 

                # now we check if we allocated the memory
                if allocated_address == None:
                    print("We don't have enough space in the heap to alocate this space, 0 was placed in RAX")
                    mu.reg_write(UC_X86_REG_RAX,0)
                    return
                else:
                    # now putting that allocated address in rax, mirroring a call to malloc
                    mu.reg_write(UC_X86_REG_RAX,allocated_address)
                self.update_logic(self.h.HEAP_SIZE, self.h.memory_list, self.h.freed_memory_list,"Allocation",allocated_address)

            if address in FREE_ADDRESSES:
                # skipping the instruction
                mu.reg_write(UC_X86_REG_RIP,address+size)

                # keeping the address of the deallocation
                free_address = mu.reg_read(UC_X86_REG_RDI)

                # now we call the deallocator function in the heap
                new_address = self.h.deallocate(free_address)

                # if the new address is not 0 then we have a problem
                if new_address != 0:
                    print("Deallocation was unsuccessfull. Something went wrong")
                    return
                else:
                # else we put 0 in RAX to be put in the stack
                    mu.reg_write(UC_X86_REG_RAX,new_address)

                self.update_logic(self.h.HEAP_SIZE, self.h.memory_list, self.h.freed_memory_list,"Deallocation",free_address)

            time.sleep(0.3) # sleeping 0.3 s after every instruction so they can be more visible on the screen
        try:
            # Initialize emulator in X86-64bit mode
            mu = Uc(UC_ARCH_X86, UC_MODE_64)

            # map 2MB memory for the code to be emulated and 4MB to the stack
            mu.mem_map(CODE_ADDRESS, 2 * SIZE_MB)
            mu.mem_map(STACK_ADDRESS, STACK_SIZE)

            # write machine code to be emulated to memory
            mu.mem_write(CODE_ADDRESS, X86_CODE64)

            # setting the base pointer to the stack
            mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 1)

            mu.hook_add(UC_HOOK_CODE, hook_code)

            # emulate code in infinite time & unlimited instructions
            mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(X86_CODE64))

            # exiting the program after the instruction are done wmulating so we dont run in an infinite loop
            exit()
            
        except UcError as e:
            print("ERROR: %s" % e)
        
    def update_logic(self,size,memory_list,freed_memory_list,string,address):

        arcade.start_render()
        
        # depending on what we need to do we modify the text
        if string == 'Allocation':
            text = "A block of size " + str(memory_list[address]) + " has been alocated, starting at address "+ str(hex(address))
        elif string == 'Deallocation':
            text = "A block of size " + str(freed_memory_list[address]) + " has been deallocated, starting at address " + str(hex(address))
        else: 
            text = ''

        # starting address and end adress of the heap
        starting_address = self.h.HEAP_ADDRESS + self.h.HEAP_SIZE - 1;
        end_address = self.h.HEAP_ADDRESS;

        # drawing the text on the screen
        arcade.draw_text(text, 100, 850, (45,168,216))
        arcade.draw_text(str(hex(starting_address)),175,100,(45,168,216))
        arcade.draw_text(str(hex(end_address)), 175, 790, (45,168,216))

        # drawing the free memory depicted as empty white rectangles
        for i in range(0,size):
            arcade.draw_lrtb_rectangle_outline(250, 500, 100+(i+1)*7, 100+i*7, arcade.csscolor.WHITE)

        # drawing the allocations in the heap as fiiled rectangles colored blue 
        for key in memory_list:
            starting_index = size - (key - self.h.HEAP_ADDRESS) - 1
            for i in range(0,memory_list[key]):
                arcade.draw_lrtb_rectangle_filled(250, 500, 100+(starting_index+i+1)*7, 100+(starting_index+i)*7, (75,135,139))

        # drawing the deallocations in the heap as filled rectangles colored red
        for key in freed_memory_list:
            starting_index = size - (key - self.h.HEAP_ADDRESS) - 1
            for i in range(0,freed_memory_list[key]):
                arcade.draw_lrtb_rectangle_filled(250, 500, 100+(starting_index+i+1)*7, 100+(starting_index+i)*7, (214,65,97))
        # finish rendering
        arcade.finish_render()



def main():
    
    # creating our emulation object
    emulator = Emulation(SCREEN_WIDTH, SCREEN_HEIGHT)
    emulator.on_draw()
    
    # running the application 
    arcade.run()


if __name__ == "__main__":
    main()
    