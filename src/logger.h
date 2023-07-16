#pragma once

#include <iostream>

struct Logger
{
    static Logger& get() noexcept;

    Logger(Logger const&) = delete;
    void operator=(Logger const&) = delete;

    enum class Level
    {
        Default,
        Verbose
    };

    ~Logger() noexcept;
private:
    Logger() noexcept;    

public:
    void set_level(Level lvl) noexcept;
    Level level() const noexcept;
    bool level_verbose() const noexcept;

    // Stream operations

    template <class T>
    Logger& operator<<(const T& t);

    // Overloads for manipulators
    Logger& operator<< (std::ostream& (*f)(std::ostream&));
    Logger& operator<< (std::ostream& (*f)(std::ios&));
    Logger& operator<< (std::ostream& (*f)(std::ios_base&));

private:
    static Logger* _instance;
    Level _enabled_level;
    std::ostream _fn;
};


// Template methods definitions
template <class T>
Logger& Logger::operator<<(const T& t)
{
    _fn << t;
    return *this;
}
