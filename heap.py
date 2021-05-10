class Heap:
    def __init__(self,address,size):
        self.HEAP_ADDRESS = address
        self.HEAP_SIZE = size
        self.freed_memory_list = {}
        self.memory_list = {}
        self.heap_pointer = self.HEAP_ADDRESS + self.HEAP_SIZE - 1;
    
    def allocate(self,size):
        # first we alocate the space iteratively starting from heap_pointer to the HEAP_ADDRESS
        if self.heap_pointer - size > self.HEAP_ADDRESS:

            return_address = self.heap_pointer
            self.heap_pointer -= size
            self.memory_list[return_address] = size;
            
            return return_address
        
        else:
            # if we used all the space then we loop through the freed memory locations
            for key in self.freed_memory_list:
                if self.freed_memory_list[key] >= size: 
                    
                    return_key = key;

                    if self.freed_memory_list[key] == size:
                        self.freed_memory_list.pop(key)
                    else:
                        key -= size;
                        remaining_size = self.freed_memory_list[return_key] - size;
                        self.freed_memory_list.pop(return_key)
                        self.freed_memory_list[key] = remaining_size

                    self.memory_list[return_key] = size

                    return return_key
        # if there is no space to allocate the object the we return None
        return None

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



    def deallocate(self,address):
        
        for key in self.memory_list:
            if key == address:
                self.freed_memory_list[key] = self.memory_list[key]
                self.memory_list.pop(key)
                return 0
        return -1
