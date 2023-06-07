#include <CoreWindow.h>
#include <cinttypes>

uint32_t rva_to_file(IMAGE_DOS_HEADER* image, uint32_t rva);
uint32_t file_to_rva(IMAGE_DOS_HEADER* image, uint32_t file);