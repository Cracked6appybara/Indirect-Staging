

.data


EXTERN NtCloseSSN:DWORD
EXTERN NtCloseSyscall:QWORD


EXTERN NtCreateThreadSSN:DWORD
EXTERN NtCreateThreadSyscall:QWORD

EXTERN NtWriteVirtualMemorySSN:DWORD
EXTERN NtWriteVirtualMemorySyscall:QWORD

EXTERN NtWaitForSingleObjectSSN:DWORD
EXTERN NtWaitForSingleObjectSyscall:QWORD

EXTERN NtAllocateVirtualMemorySSN:DWORD
EXTERN NtAllocateVirtualMemorySyscall:QWORD


.code


NtClose proc
        mov r10, rcx
        mov eax, NtCloseSSN
        jmp qword ptr [NtCloseSyscall]
        ret
NtClose endp

NtCreateThreadEx proc
        mov r10, rcx
        mov eax, NtCreateThreadSSN
        jmp qword ptr [NtCreateThreadSyscall]
        ret
NtCreateThreadEx endp

NtWriteVirtualMemory proc
        mov r10, rcx
        mov eax, NtWriteVirtualMemorySSN
        jmp qword ptr [NtWriteVirtualMemorySyscall]
        ret
NtWriteVirtualMemory endp

NtWaitForSingleObject proc
        mov r10, rcx
        mov eax, NtWaitForSingleObjectSSN
        jmp qword ptr [NtWaitForSingleObjectSyscall]
        ret
NtWaitForSingleObject endp

NtAllocateVirtualMemory proc
        mov r10, rcx
        mov eax, NtAllocateVirtualMemorySSN
        jmp qword ptr [NtAllocateVirtualMemorySyscall]
        ret
NtAllocateVirtualMemory endp
end