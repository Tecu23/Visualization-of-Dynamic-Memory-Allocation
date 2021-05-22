
# **Visualization of Dynamic Memory Allocation**

## **Functionalities**

- Simulating the heap memory allocation using some known algorithms in a program. 
- Seeing the allocation and deallocation of blocks in real-time.
- Seeing the addreses where the memory has been allocated/freed and the size.

All to better understand how the memory is being used in a real C program 

<br>

## **Install and run the application**

<br>
<br>

### **Cloning the git repository**

Clone with SSH:

    git clone git@gitlab.com:smp2021/334ab/visualization-of-dynamic-memory-allocation.git

Clone with HTTPS:

    git clone https://gitlab.com/smp2021/334ab/visualization-of-dynamic-memory-allocation.git

Move into Visualication of Dynamic Memory Allocation

    cd visualization-of-dynamic-memory-allocation

### **Installing the necessary libraries and running the application**

- Make sure you have [Python](https://www.python.org/) on your computer

First make sure you have install make, if you are on a Debian base system you can use the comand

    sudo apt install make

For installing the libraries for python 3 run the command:

    make install3

For installing the libraries for python 2 run the command:

    make install

### **Running the application**

**First we can change the heap memory allocation algorithm used by going into the heap.py file, lines 32-34
where we can comment and uncomment depending on what algoritm we want to use**

Running the application with python 3

    make run3

Running the application with python 2

    make run

### **Clean up**

Run the command:

    make clean


## **Similar Projects**

1. [Visualizing Dynamic Memory Allocations](https://core.ac.uk/download/pdf/189667001.pdf)  by Sergio Moreta and Alexandru Telea
        
2. [Visualization of Dynamic Memory in C++ Applications](https://ltu.diva-portal.org/smash/get/diva2:1337031/FULLTEXT01.pdf) by Filip Salén

3. [A Tool for Visualizing the Execution of Programs and Stack Traces Especially Suited for Novice Programmers](https://ltu.diva-portal.org/smash/get/diva2:1337031/FULLTEXT01.pdf)


## **References**

- [Unicorn-engine X86](https://github.com/unicorn-engine/unicorn) emulator to emulate the assembly code 
    

- [Shell's storm online assembler](http://shell-storm.org/online/Online-Assembler-and-Disassembler/) to assemble the code in code.asm

- Visualizing the allocation was made using the [arcade](https://arcade.academy/index.html) library

- Learning about memory allocation [algorithms](https://www.tutorialspoint.com/operating_system/os_memory_allocation_qa2.htm) used
    