mov rbp,rsp
mov rax, 4
mov [rbp-8], rax
mov rax, 5
mov [rbp-16], rax
mov edi, 100
call malloc
mov [rbp-24], rax
mov edi, 200
call malloc
mov [rbp-32], rax
mov rax,[rbp-8]
mov rbx,[rbp-16]
mov rcx,[rbp-24]
mov rdx,[rbp-32]