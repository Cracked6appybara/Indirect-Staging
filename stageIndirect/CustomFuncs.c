#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "Common.h"


//
//  HMODULE dat type is the base address of the loaded DLL which is where the DLL is located in the address space of the
//  process. This means the goal of the replacement function is to retrieve the base address of a specified DLL.
//

// The Process Environmnent Block (PEB) contains information regarding the loaded DLLs, notably the PEB_LDR_DATA Ldr
// member of the PEB structure. Thus, the initial step is to access this member through the PEB structure.





//	LOGIC:
//		1. Retrieve the PEB
//		2. Retrieve teh Ldr member from the PEB
//		3. Retrieve the first element in the linked list
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

	/*--------------------[Step 1]--------------------*/

		// Getting the peb structure. Get the offset of the PEB strcture from the gs register. (0x60)
	PPEB pPeb = (PPEB)(__readgsqword(0x60));


	/*--------------------[Step 2]--------------------*/

		//	Getting the Ldr member
		//	acces the PEB_LDR_DATA ldr member. Recall that this member contains information regarding
		//	the loaded DLLs in the process.
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);


	//	Getting the first element in the linked list which contains information about the first module
	// 
	//	The LDR_DATA_TABLE_ENTRY structure represents a DLL inside the linked list of loaded DLLs for the process	
	//	Every LDR_DATA_TABLE_ENTRY represents a unique DLL.

	//	IMPORTANT MEMBER: LIST_ENTRY InMemoryOrderModuleList.
	//	each item in this member points to a LDR_DATA_TABLE_ENTRY structure
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	/*--------------------[Step 2]--------------------*/

		// since pDte contains all of the DLLs inside of the linked list. Use this to enumerate throught the list.
	while (pDte) {

		//	If not null
		if (pDte->FullDllName.Length != NULL) {

			// Check if equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				

				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
			}



			//	Print the DLL name
			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}

		// Next element in the linke dlist
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}


BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR lStr1[MAX_PATH],
		lStr2[MAX_PATH];

	int len1 = lstrlenW(Str1),
		len2 = lstrlenW(Str2);

	int i = 0,
		j = 0;


	// Checking length. We dont want to overflow the buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// Converting Str1 to lower case string (lStr1
	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // Null terminating

	// Converting Str2 to lower case string (lStr1)
	for (j = 0; j < len1; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // Null terminating

	// Comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0) {
		return TRUE;
	}

	return FALSE;
}




//
//  hModule is the base address of the loaded DLL. this is the address where the DLL module is found in the process.
//  Retrieving a functions address is found by looping through the exported functions inside the provided DLL and
//  checking if the target function's name exists.
//

//  We need the IMAGE_EXPORT_DIRECTORY structure since it will allow us to get the relevent members we need to find the
//  functions address.

//  AddressOfFunction - Specifies the address of an array of addresses of the exported functions

//  AddressOfNames - Specifies the address of an array of address of the names of the exported functions

//  AddressOfNameOrdinals - Specifies the address of an array of ordinal n umbers for the exported functions



FARPROC GetProcAddressReplacement(IN HANDLE hModule, IN LPCSTR lpApiName) {

	/*-------------------------[Step 1]------------------------*/
	// retrieving the export directory, IMAGE_EXPORT_DIRECTORY.



		// We do this to avoid casting each time we use 'hModule'
		// This is the base address of the module (DLL).
	PBYTE pBase = (PBYTE)hModule;


	// Getting the DOS head and performing a signature check
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}


	// Getting the NT headers and performing a signature check
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}


	// Getting the optional header
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;


	// Getting the image export table
	// This is the export directory!!!
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);



	/*-------------------------[Step 2]------------------------*/





		//  Since these are RVA's the base address of the module, pBase, must be added to get the virtual address.
		//  Getting the function's name array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);

	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

	PWORD FunctionOrdinalsArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	//  loop through the exported functions. The NumberOfFunctions member specifies the number of functions
	//  exported by hModule (the DLL). With this information, we should set the max iterations of the loop
	//  to be equivalent to NumberOfFunctions.
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// Getting the ordinal of the function
		WORD wFunctionOrdinal = FunctionOrdinalsArray[i];

		// Getting the address of the function through it's ordinal
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);

		// Searching for the function specified
		if (strcmp(pFunctionName, lpApiName) == 0) {
			return pFunctionAddress;
		}


		//  Printing
		//printf("[ %0.4lu ] NAME: %s -\t ORDINAL: %d\n", i, pFunctionName, wFunctionOrdinal);
	}


	return NULL;
}