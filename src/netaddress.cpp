#include "netaddress.h"
#include "logger.h"
#include <cstring>  // for strchr
#include <cstdlib>  // for sscanf
#ifdef _WIN32
    #include <WinSock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
#endif


bool NetAddress::is_valid_ipv4(const char* address) noexcept
{
    unsigned int a, b, c, d;
    if (4 != sscanf(address, "%u.%u.%u.%u", &a, &b, &c, &d))
        return false;
    return ((a < 256) && (b < 256) && (c < 256) && (d < 256));
}


std::string NetAddress::resolve_hostname_to_ipv4(const char* hostname) noexcept
{
    std::string ip;
    Logger::get() << "- Interrogating hostname... ";

    struct addrinfo  addr_hints = {};
    struct addrinfo* addr_infoptr = nullptr;
    addr_hints.ai_family = AF_UNSPEC;

#ifdef _WIN32
    {
        WSADATA wsaData;
        const int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (wsaResult)
        {
            WCHAR* s = nullptr;
            FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, static_cast<DWORD>(wsaResult),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                reinterpret_cast<LPWSTR>(&s), 0, nullptr);
            Logger::get() << "WSock error: " << s << " (code: " << wsaResult << ")" << std::endl;
            LocalFree(s);
            return ip;
        }

        if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
            /* Tell the user that we could not find a usable WinSock DLL. */
            Logger::get() << "WSock error: could not find a usable version of WinSock.dll." << std::endl;
            goto clean_and_ret;
        }
    }
#endif

    {
        const int result_addr = getaddrinfo(hostname, nullptr, &addr_hints, &addr_infoptr);
        if (result_addr)
        {
            Logger::get() << "Error: " << gai_strerror(result_addr);
            freeaddrinfo(addr_infoptr);
            goto clean_and_ret;
        }

        Logger::get() << "Success." << std::endl;

        if (Logger::get().level_verbose())
        {
            Logger::get() << "-- Interrogating \"" << hostname << "\"... " << std::endl;
            Logger::get() << "-- Found:" << std::endl;
        }

        char host[256]{};
        for (struct addrinfo* p = addr_infoptr; p != nullptr; p = p->ai_next)
        {
            getnameinfo(p->ai_addr, static_cast<socklen_t>(p->ai_addrlen), host, sizeof(host), nullptr, 0, NI_NUMERICHOST);

            // I want the first IPv4 address that i get (not the IPv6, which has the : separators).
            if (nullptr == strchr(host, ':'))
            {
                //Logger::get() << "--> " << host << std::endl;
                ip = host;
                break;
            }
        }

        freeaddrinfo(addr_infoptr);
    }

clean_and_ret:
    #ifdef _WIN32
        WSACleanup();
    #endif
    return ip;
}