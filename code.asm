mov rbp,rsp

mov edi, 10
call 0x31       ;malloc
mov [rbp-8], rax

mov edi, 24
call 0x31       ;malloc
mov [rbp-16], rax

mov edi, 36
call 0x31       ;malloc
mov [rbp-24], rax

mov edi, 25
call 0x31       ;malloc
mov [rbp-32], rax

mov rax, [rbp-32]
mov rdi, rax
call 0x23       ;free
mov [rbp-32], rax

mov edi, 20
call 0x31       ;malloc
mov [rbp-40], rax
