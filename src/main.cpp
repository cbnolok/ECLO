#include "logger.h"
#include "clientversion.h"
#include "netaddress.h"
#include "patcher_address.h"
#include <string_view>
#include <cstdlib>
#include <process.h>

//#include "../lib/toml.hpp"


static int exit_idle()
{
    std::cout << std::endl << "Press a key to exit...";
    std::cin.get();
    return 1;
}


struct Settings
{
    std::string input_client_name;
    std::string output_client_name;
    std::string address_ip_text;
    int address_port;
    bool disable_encryption;
    bool autolaunch;
    bool verbose;
};

static Settings load_settings() noexcept
{
    static constexpr std::string_view def_input_client_name = "UOSA.exe";
    static constexpr std::string_view def_output_client_name = "UOSA_pssp.exe";
    static constexpr std::string_view def_address_ip_text = "127.0.0.1";
    static constexpr int def_address_port = 2593;
    static constexpr int def_disable_encryption = false;
    static constexpr bool def_autolaunch = false;
    static constexpr bool def_verbose = false;

    //static constexpr char section[] = "settings";
    //auto ext_settings = toml::parse_file("passepartout.toml");

    auto settings = Settings {
        def_input_client_name.data(),
        def_output_client_name.data(),
        def_address_ip_text.data(),
        def_address_port,
        def_disable_encryption,
        def_autolaunch,
        def_verbose
    };

/*
    //auto str_optional = ext_settings[section].value();
    settings.input_client_name  = ext_settings[section].value_or(def_input_client_name);
    settings.output_client_name = ext_settings[section].value_or(def_output_client_name);
    settings.address_ip_text    = ext_settings[section].value_or(def_address_ip_text);
    settings.address_port       = ext_settings[section].value_or(def_address_port);
    settings.disable_encryption = ext_settings[section].value_or(def_disable_encryption);
    settings.autolaunch         = ext_settings[section].value_or(def_autolaunch);
    settings.verbose            = ext_settings[section].value_or(def_verbose);
*/
    return settings;
}


int main()
{
    g_logger.set_level(Logger::Level::Default);
    g_logger << "Ultima Online Enhanced Client Passepartout v1.2.\n" << std::endl;

    const Settings settings = load_settings();
    if (settings.verbose)
        g_logger.set_level(Logger::Level::Verbose);

    // Is the ip address field a hostname or an ipv4 address? in the first case, resolve it
    const std::string address_ip_v4 = NetAddress::resolve_hostname_to_ipv4(settings.address_ip_text.c_str());
    if (address_ip_v4.empty())
    {
        g_logger << "Error. Can't resolve address: " << settings.address_ip_text;
        return exit_idle();
    }

    // 
    const int cliver = ClientVersion::get_from_file(settings.input_client_name);
    if (cliver == -1)
    {
        g_logger << "Error. Can't retrieve the client version from the exe: " << settings.input_client_name << std::endl;
        return exit_idle();
    }

    // Get file size    
    std::ifstream fsOriginal(settings.input_client_name, std::ios::binary);
    if (!fsOriginal)
    {
        g_logger << "Error. Can't open the client: " << settings.input_client_name << std::endl;
        return exit_idle();
    }

    fsOriginal.seekg(0, std::fstream::end);
    const size_t file_size = size_t(fsOriginal.tellg());
    fsOriginal.seekg(0, std::fstream::beg);

    // Copy file
    g_logger << "- Creating a client copy... ";
    std::fstream fsPatched(settings.output_client_name, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    if (!fsPatched)
    {
        g_logger << "Error. Can't copy the original exe to a new one with name:" << settings.output_client_name << std::endl;
        return exit_idle();
    }
    fsPatched << fsOriginal.rdbuf();
    fsPatched.seekg(0, std::fstream::beg);
    fsOriginal.close();
    g_logger << "Ok." << std::endl;


    // Patch.
    g_logger << "- Start patching... ";

    // patch_address

    const bool result = patch_address(fsPatched, file_size, cliver, address_ip_v4, settings.address_port);
    if (!result)
        return exit_idle();

    // patch_encryption...


    fsPatched.close();
    

    g_logger << "Ok." << std::endl;

    if (settings.autolaunch)
    {
        g_logger << std::endl << "Starting the patched client... " << std::endl;
#ifdef _WIN32
#define spawnl _spawnl
#endif
        spawnl(P_NOWAITO, settings.output_client_name.c_str(), settings.output_client_name.c_str(), NULL);
    }
    else
    {
        std::cout << "\nSuccessiful!" << std::endl;
        exit_idle();
    }

    return 0;
}
