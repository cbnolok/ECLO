#include "logger.h"

Logger* Logger::_instance = nullptr;

Logger& Logger::get() noexcept // static
{
    if (Logger::_instance == nullptr)
        _instance = new Logger();
    return static_cast<Logger&>(*_instance);
}

Logger::Logger() noexcept :
    _enabled_level(Level::Default),
    _fn(std::cout.rdbuf())  // For now, wrapping std::cout is enough
{
}

Logger::~Logger() noexcept
{
    if (_instance != nullptr)
        delete _instance;
}


void Logger::set_level(Level lvl) noexcept
{
    _enabled_level = lvl;
}

Logger::Level Logger::level() const noexcept
{
    return _enabled_level;
}

bool Logger::level_verbose() const noexcept
{
    return (_enabled_level >= Level::Verbose);
}


Logger& Logger::operator<< (std::ostream& (*f)(std::ostream&))
{
    f(_fn);
    return *this;
}
Logger& Logger::operator<< (std::ostream& (*f)(std::ios&))
{
    f(_fn);
    return *this;
}
Logger& Logger::operator<< (std::ostream& (*f)(std::ios_base&))
{
    f(_fn);
    return *this;
}
