#include <iostream>
#include <CoreWindow.h>

#include "../utils.h"
#include "../app.hpp"
#include "../shellcode.h"
#include "../nt.hpp"
#include "imports.hpp"

using namespace std;

int ImportObfuscationLayer::process(vector<uint8_t>& file, ClerkSection& extra) {
    cout << "[ImportObfuscationLayer] processing." << endl;
    file.reserve(file.capacity() + 0x1000);

    extra.append((uint8_t*)resolve_import, 0x400);
    extra.append((uint8_t*)resolve_descriptor_list, 0x400);

    extra.new_main = extra.cursor;

    uint8_t shellcode[]  = {
        0x51,                      // push   rcx
        0x52,                      // push   rdx
        0x41, 0x50,               // push   r8
        0x48, 0x83, 0xec, 0x40,             // sub    rsp,0x40
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00,   // movabs rcx,0x0
        0x00, 0x00, 0x00,
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00,    // movabs rdx,0x0
        0x00, 0x00, 0x00,
        0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,   // movabs r8,0x0
        0x00, 0x00, 0x00,
        0xe8, 0xfb, 0xff, 0xff, 0xff,          // call   23 <main>
        0x48, 0x83, 0xc4, 0x40,             // add    rsp,0x40
        0x41, 0x58,                   // pop    r8
        0x5a,                     // pop    rdx
        0x59,                     // pop    rcx
    };
    *(void**)(shellcode + 10) = (void*)GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualProtect"); // VirtualProtect
    *(void**)(shellcode + 20) = (void*)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA"); // LoadLibraryA
    *(void**)(shellcode + 30) = (void*)GetProcAddress(LoadLibraryA("kernel32.dll"), "GetProcAddress"); // GetProcAddress
    *(int32_t*)(shellcode + 39) = -(0x400 + 43);
    extra.append(shellcode, sizeof(shellcode));
    cout << "[ImportObfuscationLayer] finished writing shellcode." << endl;

    auto dos = (IMAGE_DOS_HEADER*)file.data();
    auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)dos + dos->e_lfanew);

    nt->OptionalHeader.DataDirectory[1].VirtualAddress += nt->OptionalHeader.DataDirectory[1].Size - sizeof(IMAGE_IMPORT_DESCRIPTOR);
    nt->OptionalHeader.DataDirectory[1].Size = 0;
    cout << "[ImportObfuscationLayer] cleared data directories." << endl;

    return 0;
}

struct ImageDirectoryExport {
    uint32_t characteristics;
    uint32_t timestamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t addr_of_functions;
    uint32_t addr_of_names;
    uint32_t addr_of_name_ordinals;
};
