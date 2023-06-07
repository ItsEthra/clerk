#pragma once

#include <string>
#include <vector>

#include "layer/core.hpp"

class Clerk {
public:
	std::vector<ALayer*> layers;
	std::vector<uint8_t> image;
	ClerkSection extra;
	std::string filename;

public:
	Clerk(std::string filename, std::vector<uint8_t> image);
	~Clerk();

	void process();
	void save();
};
