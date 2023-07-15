#pragma once

#include <iostream>

class Logger
{
public:
    enum class Level
    {
        Default,
        Verbose
    };

private:
    Level _enabled_level;
    std::ostream _fn;

public:
    Logger() noexcept;
    
    void set_level(Level lvl) noexcept;
    Level get_level() const noexcept;

    bool is_verbose() const noexcept;

    // Stream operations

    template <class T>
    Logger& operator<<(const T& t);

    // Overloads for manipulators
    Logger& operator<< (std::ostream& (*f)(std::ostream&));
    Logger& operator<< (std::ostream& (*f)(std::ios&));
    Logger& operator<< (std::ostream& (*f)(std::ios_base&));
};

extern Logger g_logger;


// Template methods definitions
template <class T>
Logger& Logger::operator<<(const T& t)
{
    _fn << t;
    return *this;
}
