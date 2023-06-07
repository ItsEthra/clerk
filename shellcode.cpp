#include "shellcode.h"

__forceinline size_t _strlen(const char* str) {
    size_t i = 0;
    while (*str != 0) {
        i += 1;
        str += 1;
    }
    return i;
}

__forceinline size_t _wstrlen(const wchar_t* str) {
    size_t i = 0;
    while ((uint16_t)*str != 0) {
        i += 1;
        str += 1;
    }
    return i;
}

__forceinline char _lowercase(char c) {
    if (c >= 'A' && c <= 'Z')
        return c + 'a' - 'A';
    else
        return c;
}

__forceinline bool _wstr_icmp_str(const wchar_t* s1, const char* s2) {
    if (_wstrlen(s1) != _strlen(s2))
        return false;

    for (int i = 0; i < _wstrlen(s1); ++i) {
        char c1 = *((char*)s1 + i * 2);
        char c2 = *(s2 + i);
        if (_lowercase(c1) != _lowercase(c2))
            return false;
    }

    return true;
}

__forceinline PEB64* get_peb() {
    return *(PEB64**)((uint64_t)NtCurrentTeb() + 0x60);
}

__forceinline uint8_t* get_module_base(const char* name) {
    auto peb = get_peb();
    auto head = CONTAINING_RECORD(peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    auto current = head;
    do {
        if (!current->BaseDllName.Buffer) continue;

        if (_wstr_icmp_str(current->BaseDllName.Buffer, name)) return (uint8_t*)current->DllBase;
        current = CONTAINING_RECORD(current->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    } while (current != head);

    return 0;
}

__declspec(noinline) void* __fastcall resolve_import(const char* dll_name, const char* import_name) {
    auto dll = get_module_base(dll_name);
    auto dos = (IMAGE_DOS_HEADER*)dll;
    auto nt = (IMAGE_NT_HEADERS*)(dll + dos->e_lfanew);
    auto export_dir = nt->OptionalHeader.DataDirectory[0];
    auto exports = (IMAGE_EXPORT_DIRECTORY*)(dll + export_dir.VirtualAddress);

    for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
        auto export_name = (const char*)(dll + *((uint32_t*)(dll + exports->AddressOfNames) + i));
        if (!strcmp(import_name, export_name)) {
            return dll + *((uint32_t*)(dll + exports->AddressOfFunctions) + i);
        }
    }

    return 0;
}

__declspec(noinline) DWORD __fastcall jump_to_original() {
    return get_peb()->ImageBaseAddress;
}

#include <iostream>

using namespace std;

__declspec(noinline) void __fastcall resolve_descriptor_list(fn_virtual_protect protect, fn_load_library load_library, fn_get_proc_address get_proc_address) {
    auto base = get_peb()->ImageBaseAddress;
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)dos + dos->e_lfanew);

    auto import_dir = nt->OptionalHeader.DataDirectory[1];
    if (import_dir.VirtualAddress == 0) return;

    // auto num_of_desc = import_dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1;
    auto descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(base + import_dir.VirtualAddress) - 1;
    
    for (int i = 0; i < 1; ++i) {
        auto desc = descriptors[i];
        auto dll_name = (const char*)(base + desc.Name);

        auto thunks = (uint64_t*)(base + desc.OriginalFirstThunk);
        uint32_t j = 0;
        while (*thunks != 0) {
            auto import_name = (const char*)(base + *thunks + 2);
            auto lib = load_library(dll_name);
            auto addr = get_proc_address(lib, import_name);

            DWORD old;
            protect((LPVOID)(base + desc.FirstThunk + j * 8), 8, PAGE_READWRITE, &old);
            *(void**)(base + desc.FirstThunk + j * 8) = addr;
            protect((LPVOID)(base + desc.FirstThunk + j * 8), 8, old, &old);

            thunks += 1;
            j += 1;
        }
    }
}
