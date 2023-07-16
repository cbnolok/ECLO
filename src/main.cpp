#include "logger.h"
#include "clientversion.h"
#include "netaddress.h"
#include "patcher_address.h"
#include <filesystem>
#include <string_view>
#ifdef _WIN32
    #include <process.h>    //_spawnl
#else
    #include <spawn.h>      //posix_spawnl
#endif

#include "../lib/toml.hpp"


static int exit_idle()
{
    std::cout << std::endl << "Press enter to exit...";
    std::cin.get();
    return 1;
}

static bool myspawn(const char* filename)
{
    // true: success
#ifdef _WIN32
    return -1 ==_spawnl(P_NOWAITO, filename, filename, NULL);
#else
    pid_t pid;
    char *arg[] = {(char *)NULL};
    return 0 != posix_spawn(&pid, filename, NULL, NULL, arg, arg);
#endif
}

struct Settings
{
    std::string input_client_name;
    std::string output_client_name;
    std::string address_ip_text;
    int address_port;
    bool disable_encryption;
    bool autolaunch;
    bool level_verbose;
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

    static constexpr char file_name[] = "eclo.toml";
    static constexpr char section_name[] = "settings";

    auto settings = Settings {
        def_input_client_name.data(),
        def_output_client_name.data(),
        def_address_ip_text.data(),
        def_address_port,
        def_disable_encryption,
        def_autolaunch,
        def_verbose
    };

    if (!std::filesystem::exists(file_name))
    {
        Logger::get() << "Warning: settings file not found. Using defaults.\n" << std::endl;
        return settings;
    }
    
    auto ext_settings = toml::parse_file(file_name);
    if (!ext_settings.contains(section_name))
    {
        Logger::get() << "Warning: malformed settings file. Using defaults." << std::endl;
        return settings;
    }

    auto const& section = ext_settings[section_name];
    if (auto val = section["input_client_name"].value<std::string_view>())
        settings.input_client_name = val.value();
    if (auto val = section["output_client_name"].value<std::string_view>())
        settings.output_client_name = val.value();
    if (auto val = section["address_ip_string"].value<std::string_view>())
        settings.address_ip_text = val.value();
    if (auto val = section["address_port"].value<int>())
        settings.address_port = val.value();
    if (auto val = section["disable_encryption"].value<bool>())
        settings.disable_encryption = val.value();
    if (auto val = section["autolaunch"].value<bool>())
        settings.autolaunch = val.value();
    if (auto val = section["verbose"].value<bool>())
        settings.level_verbose = val.value();

    return settings;
}


int main()
{
    Logger::get().set_level(Logger::Level::Default);
    Logger::get() << "Ultima Online Enhanced Client Passepartout v1.3.\n" << std::endl;

    const Settings settings = load_settings();
    if (settings.level_verbose)
        Logger::get().set_level(Logger::Level::Verbose);


    if (!std::filesystem::exists(settings.input_client_name))
    {
        Logger::get() << "Error. Can't find the client exe: " << settings.input_client_name << std::endl;
        return exit_idle();
    }

    // Is the ip address field a hostname or an ipv4 address? in the first case, resolve it
    const std::string address_ip_v4 = NetAddress::resolve_hostname_to_ipv4(settings.address_ip_text.c_str());
    if (address_ip_v4.empty())
    {
        Logger::get() << "Error. Can't resolve address: " << settings.address_ip_text;
        return exit_idle();
    }

    //
    const int cliver = ClientVersion::get_from_file(settings.input_client_name);
    if (cliver == -1)
    {
        Logger::get() << "Error. Can't retrieve the client version from the exe: " << settings.input_client_name << std::endl;
        return exit_idle();
    }

    // Get file size    
    std::ifstream fsOriginal(settings.input_client_name, std::ios::binary);
    if (!fsOriginal)
    {
        Logger::get() << "Error. Can't open the client: " << settings.input_client_name << std::endl;
        return exit_idle();
    }

    fsOriginal.seekg(0, std::fstream::end);
    const size_t file_size = size_t(fsOriginal.tellg());
    fsOriginal.seekg(0, std::fstream::beg);

    // Copy file
    Logger::get() << "- Creating a client copy... ";
    std::fstream fsPatched(settings.output_client_name, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc);
    if (!fsPatched)
    {
        Logger::get() << "Error. Can't copy the original exe to a new one with name:" << settings.output_client_name << std::endl;
        return exit_idle();
    }
    fsPatched << fsOriginal.rdbuf();
    fsPatched.seekg(0, std::fstream::beg);
    fsOriginal.close();
    Logger::get() << "Ok." << std::endl;


    // Patch.
    Logger::get() << "- Start patching... ";

    // patch_address

    const bool result = patch_address(fsPatched, file_size, cliver, address_ip_v4, settings.address_port);
    if (!result)
        return exit_idle();

    // patch_encryption...


    fsPatched.close();
    

    Logger::get() << "Ok." << std::endl;

    if (settings.autolaunch)
    {
        Logger::get() << std::endl << "Starting the patched client... ";
        const bool success = myspawn(settings.output_client_name.c_str());
        Logger::get() << std::endl << (success ? "success" : "error") << std::endl;
    }
    else
    {
        std::cout << "\nSuccessiful!" << std::endl;
        exit_idle();
    }

    return 0;
}
