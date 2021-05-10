from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from heap import Heap
import time
import arcade
from constants import *

class MyGame(arcade.Window):
    """ Main application class. """

    # created the heap memory with that address and size
    h = Heap(HEAP_ADDRESS,HEAP_SIZE)

    def __init__(self, width, height):
        
        super().__init__(width, height)
        arcade.set_background_color(arcade.color.AMAZON)

    def setup(self):
        # Set up your game here
        pass
        

    def on_draw(self):
        """ Render the screen. """
       
        self.draw_big_rectangle(self.h.HEAP_SIZE)
        

    def update(self, delta_time):
        """ All the logic to move, and the game logic goes here """
        def hook_code(mu, address, size, user_data):
            print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 

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
                else:
                    # now putting that allocated address in rax, mirroring a call to malloc
                    mu.reg_write(UC_X86_REG_RAX,allocated_address)

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
                else:
                # else we put 0 in RAX to be put in the stack
                    mu.reg_write(UC_X86_REG_RAX,new_address)
            self.update_logic(self.h.HEAP_SIZE, self.h.memory_list, self.h.freed_memory_list)

            time.sleep(1)

        print("Emulate i386 code")
        try:
            # Initialize emulator in X86-32bit mode
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

            exit()
            
        except UcError as e:
            print("ERROR: %s" % e)
        


    def draw_big_rectangle(self,size):

        arcade.start_render()
        arcade.draw_lrtb_rectangle_outline(200, 400, 800, 100, arcade.csscolor.BLACK)
        for i in range(0,size):
            arcade.draw_lrtb_rectangle_outline(200, 400, 100+(i+1)*7, 100+i*7, arcade.csscolor.WHITE)

        arcade.finish_render()

    def update_logic(self,size,memory_list,freed_memory_list):

        arcade.start_render()
        
        arcade.draw_lrtb_rectangle_outline(200, 400, 800, 100, arcade.csscolor.BLACK)
        for i in range(0,size):
            arcade.draw_lrtb_rectangle_outline(200, 400, 100+(i+1)*7, 100+i*7, arcade.csscolor.WHITE)

        for key in memory_list:
            starting_index = size - (key - self.h.HEAP_ADDRESS) - 1
            for i in range(0,memory_list[key]):
                arcade.draw_lrtb_rectangle_filled(200, 400, 100+(starting_index+i+1)*7, 100+(starting_index+i)*7, arcade.csscolor.LIGHT_SKY_BLUE)

        for key in freed_memory_list:
            starting_index = size - (key - self.h.HEAP_ADDRESS) - 1
            for i in range(0,freed_memory_list[key]):
                arcade.draw_lrtb_rectangle_filled(200, 400, 100+(starting_index+i+1)*7, 100+(starting_index+i)*7, arcade.csscolor.DARK_BLUE)
        arcade.finish_render()



def main():
    game = MyGame(SCREEN_WIDTH, SCREEN_HEIGHT)
    game.setup()
    game.on_draw()
    arcade.run()


if __name__ == "__main__":
    main()
    