class Heap:
    def __init__(self,address,size):
        self.HEAP_ADDRESS = address
        self.HEAP_SIZE = size
        self.freed_memory_list = {}
        self.memory_list = {}
        self.heap_pointer = self.HEAP_ADDRESS + self.HEAP_SIZE - 1;
    
    def allocate(self,size):
        # first we alocate the space iteratively starting from heap_pointer to 0
        if self.heap_pointer - size > 0:

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
                        self.freed_memory_list[key] -= size

                    self.memory_list[key] = size

                    return return_key
        # if there is no space to allocate the object the we return 0
        return None

    def print(self):
        print(self.heap_pointer)

        for item in self.memory_list:
            print(item ,"/", self.memory_list[item] ,"/")