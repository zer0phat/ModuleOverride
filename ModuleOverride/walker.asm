.data
    dllName db 'KERNELBASE.dll', 0

.code
getLib proc
    xor rax, rax
    xor rcx, rcx
    mov rax, GS:[60h]
    mov rax, [rax + 18h]
    add rax, 10h
l1:
    call nextMod
    mov rax, rsi
    add rsi, 58h
    add rsi, 8h
    mov rsi, [rsi]
    lea rdi, dllName

    l2:
        mov bl, [rdi]
        mov cl, [rsi]

        test bl, bl
        jz exit

        cmp bl, cl
        jne l1

        inc rdi
        add rsi, 2
        jmp l2

exit:
    add rax, 30h
    mov rax, [rax]
    ret
getLib endp

nextMod proc
    xor rsi, rsi
    mov rsi, [rax]
    ret
nextMod endp

end