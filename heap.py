import numpy as np # for representing infinity

class Heap:
    # constructor for initializing the heap object with the address and size and setting the internal pointer at the bottom
    def __init__(self,address,size):
        self.HEAP_ADDRESS = address
        self.HEAP_SIZE = size
        self.freed_memory_list = {}
        self.memory_list = {}
        self.heap_pointer = self.HEAP_ADDRESS + self.HEAP_SIZE - 1;
    

    # the allocation uses FIRST FIT as an algorithm for allocations
    # as an update we could add NEXT FIT / BEST FIT / WORST FIT / BUDDY'S SYSTEM as ways of allocationg memory
    def allocate(self,size):
        # first we alocate the space iteratively starting from heap_pointer to the HEAP_ADDRESS
        if self.heap_pointer - size > self.HEAP_ADDRESS:

            # if there is place for the allocation then we allocated and move the heap_pointer
            return_address = self.heap_pointer
            self.heap_pointer -= size

            # putting the adress and size of the allocation in the memory_list
            self.memory_list[return_address] = size;
            
            return return_address
        
        else:
            # if we used don't have enough space then we loop through the freed memory locations
            # uncomment the memory allocation algorithm of choice and comment the rest

            return_address = self.search_FIRST_FIT(size)
            # return_address = self.search_BEST_FIT(size)    
            # return_address = self.search_WORST_FIT(size)

            if return_address != None:
                return return_address
        # if there is no space to allocate the object the we return None
        return None

    # printing function for debugging the program
    def print(self):
        print("POINTER TO THE HEAP",hex(self.heap_pointer))

        print("MEMORY LIST \n")
        for item in self.memory_list:
            print(hex(item) ,"-", self.memory_list[item])
        print()

        print("FREED MEMORY LIST \n")
        for item in self.freed_memory_list:
            print(hex(item) ,"-", self.freed_memory_list[item])
        print()


    # the deallocations is made by just removing the address and size from the memory_list and adding it to the freed_memory_list
    # if the heap would contain values then we would need to delete those values first
    def deallocate(self,address):
        
        for key in self.memory_list:
            if key == address:
                self.freed_memory_list[key] = self.memory_list[key]
                self.memory_list.pop(key)
                return 0
        return -1

    # used for finding the first memory location where we can allocate
    def search_FIRST_FIT(self,size):
        for key in self.freed_memory_list:
            if self.freed_memory_list[key] >= size: 
                    
                return_key = key;
                # if the space required is equal to the space available the we just remove the address and size
                if self.freed_memory_list[key] == size:
                    self.freed_memory_list.pop(key)
                # else we modify the space available to shrink after an allocation
                else:
                    key -= size;
                    remaining_size = self.freed_memory_list[return_key] - size;
                    self.freed_memory_list.pop(return_key)
                    self.freed_memory_list[key] = remaining_size

                self.memory_list[return_key] = size

                return return_key
        return None

    # used for finding the best memory location where we can allocate the memory
    def search_BEST_FIT(self,size):
        return_key = 0;
        min_space = np.inf

        for key in self.freed_memory_list:
            if self.freed_memory_list[key] >= size:
                if self.freed_memory_list[key] - size < min_space:
                    min_space = self.freed_memory_list[key] - size
                    return_key = key

        if min_space == np.inf:
            return None
        
        if min_space == 0:
            self.freed_memory_list.pop(return_key)
        else:
            new_key = return_key - size
            new_size = self.freed_memory_list[return_key] - size;
            self.freed_memory_list.pop(return_key)
            self.freed_memory_list[new_key] = new_size
        
        self.memory_list[return_key] = size

        return return_key

        
    def search_WORST_FIT(self,size):
        return_key = 0;
        min_space = -np.inf

        for key in self.freed_memory_list:
            if self.freed_memory_list[key] >= size:
                if self.freed_memory_list[key] - size > min_space:
                    min_space = self.freed_memory_list[key] - size
                    return_key = key

        if min_space == -np.inf:
            return None
        
        if min_space == 0:
            self.freed_memory_list.pop(return_key)
        else:
            new_key = return_key - size
            new_size = self.freed_memory_list[return_key] - size;
            self.freed_memory_list.pop(return_key)
            self.freed_memory_list[new_key] = new_size
        
        self.memory_list[return_key] = size

        return return_key