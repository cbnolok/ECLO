#pragma once

#include <fstream>
#include <string>

bool patch_encryption(std::fstream& fs, const size_t file_size, const int client_version);