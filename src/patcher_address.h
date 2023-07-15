#pragma once

#include <fstream>
#include <string>

bool patch_address(std::fstream& fs, const size_t file_size, const int client_version, const std::string& ip, const int port);
