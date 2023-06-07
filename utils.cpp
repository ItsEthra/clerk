#include "utils.h"

uint32_t rva_to_file(IMAGE_DOS_HEADER* image, uint32_t rva) {
    auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)image + image->e_lfanew);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto section = (IMAGE_SECTION_HEADER*)((uint8_t*)nt + sizeof(IMAGE_NT_HEADERS)) + i;
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->SizeOfRawData)
            return section->PointerToRawData + (rva - section->VirtualAddress);
    }

    return 0;
}

uint32_t file_to_rva(IMAGE_DOS_HEADER* image, uint32_t file) {
    auto nt = (IMAGE_NT_HEADERS*)((uint8_t*)image + image->e_lfanew);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto section = (IMAGE_SECTION_HEADER*)((uint8_t*)nt + sizeof(IMAGE_NT_HEADERS)) + i;
        if (file >= section->PointerToRawData && file < section->PointerToRawData + section->SizeOfRawData)
            return section->VirtualAddress + (file - section->PointerToRawData);
    }

    return 0;
}

