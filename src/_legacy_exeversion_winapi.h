#pragma once

#include <string>
#include <vector>

class ExeVersion_WinAPI
{
public:
    static std::vector<int> getExeVersion(std::string filePath);
};

