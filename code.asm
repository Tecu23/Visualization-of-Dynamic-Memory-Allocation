mov rbp,rsp

mov edi, 10
call 0x31       ;malloc
mov [rbp-8], rax

mov edi, 25
call 0x31       ;malloc
mov [rbp-16], rax

mov edi, 35
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

mov rax, [rbp-16]
mov rdi, rax
call 0x23       ;free
mov [rbp-16], rax

mov edi, 5
call 0x31       ;malloc
mov [rbp-48], rax

mov rax, [rbp-8]
mov rdi, rax
call 0x23       ;free
mov [rbp-8], rax

mov edi, 10
call 0x31       ;malloc
mov [rbp-16], rax

mov rax, [rbp-24]
mov rdi, rax
call 0x23       ;free
mov [rbp-24], rax

mov rax, [rbp-48]
mov rdi, rax
call 0x23       ;free
mov [rbp-48], rax

mov edi, 20
call 0x31       ;malloc
mov [rbp-32], rax
