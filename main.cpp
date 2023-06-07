#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>

#include "app.hpp"
#include "shellcode.h"
#include <TlHelp32.h>

using namespace std;
namespace fs = std::filesystem;

int main(int argc, char** argv) {
	string filename;
	if (argc != 2) {
		cout << "Usage: ./clerk-cli <file.exe>";
		return 1;
	}
	else filename = argv[1];

	if (!fs::exists(filename)) {
		cout << "File " << filename << " couldn't be found" << endl;
		return 2;		
	}

	ifstream target(filename, ios::binary | ios::in);
	vector<uint8_t> contents;

	copy(istreambuf_iterator<char>(target),
			 istreambuf_iterator<char>(),
			 back_inserter(contents));

	Clerk app(filename, contents);
	app.process();
	app.save();

	return 0;
}
