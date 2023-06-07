#pragma once

#include <cstdint>

#include "core.hpp"

class ImportObfuscationLayer : public ALayer {
	virtual int process(std::vector<uint8_t>& file, ClerkSection& extra) override;

private:
	IMAGE_DATA_DIRECTORY* reloc_dir;
	IMAGE_BASE_RELOCATION* reloc_block;
	uint16_t* reloc_cursor;
};
