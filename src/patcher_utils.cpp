#include "patcher_utils.h"

bool find_bytes(size_t* position, std::fstream& fs, const size_t file_size, const byte* bytes, const size_t bytes_size)
{
    if (!fs.good())
        return false;

    byte buf = 0;
    size_t pos = size_t(fs.tellg());
    while (pos < file_size)
    {
        bool found = false;
        if (position != nullptr)
            *position = pos;

        for (size_t offset_array = 0; (offset_array < bytes_size) && (pos < file_size); ++offset_array)
        {
            fs.read(reinterpret_cast<char*>(&buf), 1);
            ++pos;
            if (buf != bytes[offset_array])
            {
                found = false;
                break;
            }
            else
                found = true;
        }
        if (found)
            return true;
    }

    return false;
}
