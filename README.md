    Title: 
    
    Visualization of Dynamic Memory Allocation


    Functionalities:

        Given some c code that uses multiple calls to malloc/calloc and free it emulates it using the unicorn engine and retrieves
    the memory location that was just allocated or freed to better understand the functionality of those calls.





Similar Projects:

    - Visualizing Dynamic Memory Allocations  by Sergio Moreta and Alexandru Telea
        https://core.ac.uk/download/pdf/189667001.pdf

    - Visualization of Dynamic Memory in C++ Applications by Filip Salén
        https://ltu.diva-portal.org/smash/get/diva2:1337031/FULLTEXT01.pdf

    - A Tool for Visualizing the Execution of Programs and Stack Traces Especially Suited for Novice Programmers
        https://www.scitepress.org/papers/2017/63369/63369.pdf



Refences:

    - usign unicorn-engine X86 emulator from:
    https://github.com/unicorn-engine/unicorn

    - online assembler to assemble the code in code.asm
    http://shell-storm.org/online/Online-Assembler-and-Disassembler/

    - for the visualization I used  the missingno library
        Bilogur, (2018). Missingno: a missing data visualization suite. Journal of Open Source Software, 3(22), 547, 
    https://doi.org/10.21105/joss.00547