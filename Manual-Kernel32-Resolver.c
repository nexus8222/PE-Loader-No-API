/*
    Hey everyone, it's Nexus here.

    Today I pushed myself deep into the core of Windows internals and wrote something wild — 
    a manual API resolver in C, no Windows APIs, no imports, nothing fancy — just raw memory parsing.

    This program finds the base address of `kernel32.dll` by walking through the PEB (Process Environment Block), 
    parses the PE headers manually, locates the Export Address Table, and resolves all exported function names 
    and their addresses — just like how a shellcode or custom loader would do it in a real malware scenario.

    As someone still learning low-level C and systems programming, this was intense.
    But seeing it work? Pure satisfaction. No shortcuts, no helper functions — just raw logic and 
    a deep dive into Windows internals.

    Give it a try. Step through the code. You’ll learn more here than any tutorial can teach.
*/


#include <stdio.h>
#include <winnt.h>  

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef void *PRTL_USER_PROCESS_PARAMETERS;
typedef void (*PPS_POST_PROCESS_INIT_ROUTINE)(void);

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, *PPEB;


typedef struct _PE_HEADER {
    IMAGE_DOS_HEADER DosHeader;          // DOS Header
    IMAGE_NT_HEADERS NtHeaders;          // NT Headers
    IMAGE_EXPORT_DIRECTORY ExportTable;  // Export Directory
} PE_HEADER, *PPE_HEADER;


#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))
#endif
int main() {
    
    //getting kernal base memory address from PEB AND TEB
    PPEB peb = NULL;
    PVOID kernel32Base;

    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));

    printf("PEB Address: 0x%p\n", peb);
    printf("LDR Address: 0x%p\n", peb->Ldr);

    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY *moduleList = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *current = moduleList->Flink;

    while (current != moduleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        
        wprintf(L"Loaded Module: %wZ\n", &entry->BaseDllName);
        if (_wcsicmp(entry->BaseDllName.Buffer, L"kernel32.dll") == 0) {
            kernel32Base = entry->DllBase;
        }

        current = current->Flink;
    }
    printf("kernel32.dll base at: 0x%p\n", kernel32Base);


    //this is for getting PE(PORTABLE EXECUTABLE) HEADERS from PE format of file
    PIMAGE_DOS_HEADER img = (PIMAGE_DOS_HEADER)kernel32Base;
    if (img->e_magic != IMAGE_DOS_SIGNATURE){
        printf("INVALID DOS SIGNATURE DITACTED!!\n");
        return 1;
    }

    PIMAGE_NT_HEADERS nt_img =(PIMAGE_NT_HEADERS)((BYTE*)kernel32Base + img->e_lfanew);
    if (nt_img->Signature != IMAGE_NT_SIGNATURE){
        printf("Invalid NT signature!\n");
        return 1;
    }

    //this portion is used for getting all the sections from that NT HEADER OF PE FORMAT
    int total_section = nt_img->FileHeader.NumberOfSections;
    printf("IMAGE BASE:0x%p\n",nt_img->OptionalHeader.ImageBase);
    PIMAGE_SECTION_HEADER nt_section = IMAGE_FIRST_SECTION(nt_img);
    printf("FIRST SECTION ADDRESS: 0x%p\n",nt_section);
    
    for (int i = 0; i < total_section; i++ , nt_section++)
    {
        printf("SECTION %d: %s\n",i+1,nt_section->Name);
    }
    
    //THIS portion of code is for GETTING ALL the exported functions from EXPORT TABLE!

    DWORD export_dir = nt_img->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    /*in this lower code i am doing airthmetic operation where i am moving kernal base add pointer by its RELATIVE
    VIRTUAL ADDRESS Adding it to the base address correctly translates it into an actual pointer we can use.*/
    PIMAGE_EXPORT_DIRECTORY dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)kernel32Base + export_dir);
    DWORD* nameRVAs = (DWORD*)((BYTE*)kernel32Base + dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)kernel32Base + dir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)((BYTE*)kernel32Base + dir->AddressOfFunctions);
    DWORD num = dir->NumberOfNames;
    

    for (DWORD i = 0; i < num; i++) {
        const char* funcName = (const char*)((BYTE*)kernel32Base + nameRVAs[i]);
        WORD ordinalIndex = ordinals[i];
        DWORD funcRVA = funcRVAs[ordinalIndex];
        void* funcAddr = (BYTE*)kernel32Base + funcRVA;

        printf("%3d: %-30s Address: %p\n", i + 1, funcName, funcAddr);
    }


    return 0;
}
