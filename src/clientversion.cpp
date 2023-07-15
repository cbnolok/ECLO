#include "clientversion.h"
#include "exeversion.h"
#include "logger.h"

int ClientVersion::get_from_file(std::string_view filename) noexcept
{
    if (g_logger.is_verbose())
    {
        g_logger << "- Retrieving client version... ";
    }

    std::vector<int> ver = ExeVersion::get_from_file(filename);
    if (ver.empty())
    {
        return -1;
    }

    const int ver_major = ver[0];
    const int ver_minor = ver[1];
    const int ver_build = ver[2];
    const int ver_revision = ver[3];

    const int cliver = (ver_revision + (ver_build * 100) + (ver_minor * 10000) + (ver_major * 1000000));

    if (g_logger.is_verbose())
    {
        g_logger << "Success." << std::endl;
        g_logger << "--> Version: " << ver_major << "." << ver_minor << "." << ver_build << "." << ver_revision << std::endl;
        g_logger << "--> Is Time Of Legends or above? " << isTOL(cliver) << std::endl;
    }

    return cliver;
}