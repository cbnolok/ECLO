#pragma once

#include <string_view>

namespace ClientVersion
{
	int get_from_file(std::string_view filename) noexcept;
	inline bool isTOL(int clientversion) noexcept {
		return (clientversion > 4004000);
	}
};
