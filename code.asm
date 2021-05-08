mov rbp,rsp
mov rax, 4
mov [rbp-4], rax
mov rax, 5
mov [rbp-4], rax
mov edi, 6
call malloc
mov [rbp-8], rax
mov rax,[rbp-4]
mov rbx,[rbp-8]
mov rcx,[rbp-12]