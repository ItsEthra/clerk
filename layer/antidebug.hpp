#pragma once

#include <cstdint>

#include "core.hpp"

class AntidebugLayer : public ALayer {
	virtual int process(std::vector<uint8_t>& file, ClerkSection& extra) override;
};
