#include <algorithm>
#include <iostream>
#include <fstream>
#include <CoreWindow.h>

#include "app.hpp"
#include "layer/imports.hpp"
#include "layer/antidebug.hpp"

using namespace std;

Clerk::Clerk(std::string filename, std::vector<uint8_t> image) : filename(filename), image(image) {
    auto dos = (IMAGE_DOS_HEADER*)image.data();
    auto nt = (IMAGE_NT_HEADERS*)(image.data() + dos->e_lfanew);

    extra.rva = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i += 1) {
        auto section = (IMAGE_SECTION_HEADER*)((uint8_t*)nt + sizeof(IMAGE_NT_HEADERS)) + i;
        if (section->VirtualAddress + section->SizeOfRawData > extra.rva) {
            extra.rva = section->VirtualAddress + section->SizeOfRawData;
        }
        cout << "Section " << (const char*)(&section->Name) << " Characteristics: " << section->Characteristics << endl;
    }
    extra.rva |= 0xFFF; extra.rva += 1;

    cout << "Extra section RVA: 0x" << hex << extra.rva << endl;

    layers.push_back(new ImportObfuscationLayer());
    layers.push_back(new AntidebugLayer());
}

Clerk::~Clerk() {
    for (auto ptr : layers) {
        delete ptr;
    }
}


void Clerk::process() {
    for (auto layer_ptr : layers) {
        layer_ptr->process(image, extra);
    }
}

void Clerk::save() {
    std::vector<uint8_t> joined = this->image;
    joined.reserve(joined.capacity() + 0x1000);

    auto dos = (IMAGE_DOS_HEADER*)joined.data();
    auto nt = (IMAGE_NT_HEADERS*)(joined.data() + dos->e_lfanew);
    auto section = (IMAGE_SECTION_HEADER*)((uint8_t*)nt + sizeof(IMAGE_NT_HEADERS)) + nt->FileHeader.NumberOfSections;

    uint8_t shellcode[] = {
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x48, 0x60,
        0x48, 0x8B, 0x41, 0x10,
        0x49, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0x4C, 0x01, 0xF8,
        0xFF, 0xE0,
        0xC3,
        0xCC
    };
    *(uint64_t*)(shellcode + 19) = nt->OptionalHeader.AddressOfEntryPoint;
    extra.append(shellcode, sizeof(shellcode));

    while (extra.content.size() % 0x1000 != 0) extra.content.push_back(0);
    joined.insert(joined.end(), this->extra.content.begin(), this->extra.content.end());

    nt->FileHeader.NumberOfSections += 1;
    nt->OptionalHeader.SizeOfImage = extra.rva + extra.content.size();
    cout << "New entry point: " << extra.rva << " plus " << extra.new_main << endl;
    nt->OptionalHeader.AddressOfEntryPoint = extra.rva + extra.new_main;

/*
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
*/

    memset(section->Name, 0, IMAGE_SIZEOF_SHORT_NAME);
    section->Name[0] = '.';
    section->Name[1] = 'c';
    section->Name[2] = 'l';
    section->Name[3] = 'e';
    section->Name[4] = 'r';
    section->Name[5] = 'k';

    section->Misc.VirtualSize = extra.content.size();
    section->VirtualAddress = extra.rva;
    section->SizeOfRawData = extra.content.size();
    section->PointerToRawData = image.size();
    section->PointerToRelocations = 0;
    section->PointerToLinenumbers = 0;
    section->NumberOfRelocations = 0;
    section->NumberOfLinenumbers = 0;
    section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    ofstream fout("out.clerk.exe", ios::out | ios::binary);
    fout.write((const char*)joined.data(), joined.size());
    fout.close();

    // TODO: Save file.
}
