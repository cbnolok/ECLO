#include "logger.h"

//Logger g_logger;


Logger::Logger() noexcept :
    _enabled_level(Level::Default),
    _fn(std::cout.rdbuf())  // For now, wrapping std::cout is enough
{
}


void Logger::set_level(Level lvl) noexcept
{
    _enabled_level = lvl;
}

Logger::Level Logger::get_level() const noexcept
{
    return _enabled_level;
}

bool Logger::is_verbose() const noexcept
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
