/*
    file that contains printf & wprinf replacements
*/

#pragma once

#include <Windows.h>

// uncomment to enable debug mode
//
#define DEBUG



#ifdef DEBUG

// wprintf replacement
#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


// printf replacement
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  



#endif // DEBUG



// The `extern` keyword sets the `memset` function as an external function.
extern void* __cdecl memset(void*, int, size_t);

// The `#pragma intrinsic(memset)` and #pragma function(memset) macros are Microsoft-specific compiler instructions.
// They force the compiler to generate code for the memset function using a built-in intrinsic function.
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
    // logic similar to memset's one
    unsigned char* p = (unsigned char*)Destination;
    while (Size > 0) {
        *p = (unsigned char)Value;
        p++;
        Size--;
    }
    return Destination;
}

CHAR _toUpper(CHAR C)
{
    if (C >= 'a' && C <= 'z')
        return C - 'a' + 'A';

    return C;
}

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
    for (volatile int i = 0; i < Size; i++) {
        ((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
    }
    return Destination;
}
