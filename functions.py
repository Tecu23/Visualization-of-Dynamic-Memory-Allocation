def allocate(heap_pointer,size,memory_list):

    # first we alocate the space iteratively starting from heap_pointer to 0

    if heap_pointer - size > 0:

        return_address = heap_pointer
        
        heap_pointer -= size
        
        memory_list[return_address] = size;
        
        return return_address
    
    else:
        # if we used all the space then we loop through the freed memory locations
        for key in freed_memory_list:
            if freed_memory_list[key] >= size: 
                
                return_key = key;

                if freed_memory_list[key] == size:
                    freed_memory_list.pop(key)
                else:
                    key -= size;
                    freed_memory_list[key] -= size

                memory_list[key] = size

                return return_key
    # if there is no space to allocate the object the we return 0
    return None;

