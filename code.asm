mov rbp,rsp
mov edi, 100000
call 0x31       ;malloc
mov [rbp-8], rax
mov edi, 200000
call 0x31       ;malloc
mov [rbp-16], rax
mov edi, 300000
call 0x31       ;malloc
mov [rbp-24], rax
mov edi, 400000
call 0x31       ;malloc
mov [rbp-32], rax

mov rax, [rbp-32]
mov rdi, rax
call 0x23       ;free
mov [rbp-32], rax

mov edi, 4000
call 0x31       ;malloc
mov [rbp-40], rax

mov rax,[rbp-8]
mov rbx,[rbp-16]
mov rcx,[rbp-24]
mov rdx,[rbp-32]
mov r10,[rbp-40]