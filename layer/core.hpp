#pragma once

#include <vector>
#include <cstdint>

struct ClerkSection {
	std::vector<uint8_t> content;
	uint32_t cursor;
	uint32_t rva;
	uint32_t new_main;

	ClerkSection();
	void append(const uint8_t* ptr, size_t size);
};

// Defines a single layer of obfuscation.
class ALayer {
public:
	// Modifies file inplace.
	virtual int process(std::vector<uint8_t>& file, ClerkSection& section) = 0;
	virtual ~ALayer() {};
};
