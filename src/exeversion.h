#pragma once

#include <string_view>
#include <vector>


namespace ExeVersion
{
    std::vector<int> get_from_file(std::string_view filePath) noexcept;
};

