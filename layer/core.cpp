#include "core.hpp"

ClerkSection::ClerkSection()
{
    cursor = 0;
    rva = 0;
    new_main = 0;
    content = {};
}

void ClerkSection::append(const uint8_t* ptr, size_t size)
{
    content.reserve(content.capacity() + size);
    for (int i = 0; i < size; ++i) {
        content.push_back(ptr[i]);
    }
    cursor += size;
}