#pragma once

#include <string>

namespace NetAddress
{
	bool is_valid_ipv4(const char* address) noexcept;
	std::string resolve_hostname_to_ipv4(const char* hostname) noexcept;
};
