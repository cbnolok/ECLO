/* 
 * Originally taken from the answer by @rodrigo, found here: http://stackoverflow.com/a/12486703/850326
 * It was distributed under the CC-wiki license.
 * user contributions licensed under cc by-sa 3.0 with attribution required: https://creativecommons.org/licenses/by-sa/3.0/
 */

#include "exeversion.h"
#include "patcher_utils.h"
#include <sys/stat.h>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>


static const char* searchVersionResource(size_t bufSize, const char* buf);
static std::vector<int> extractVersionFromResource(size_t bufSize, const char* versionResource);

std::vector<int> ExeVersion::get_from_file(std::string_view filePath) noexcept
{
    struct stat st;
    if (stat(filePath.data(), &st) < 0)
        return {};

    std::ifstream fs(filePath.data(), std::ios::binary);
    if (!fs)
        return {};

    size_t bufSize = signed_to_unsigned_floor(st.st_size);
    auto buf = std::make_unique<char[]>(bufSize);

    fs.read(buf.get(), unsigned_to_signed_ceil(bufSize));
    fs.close();

    try
    {
        const char* versionResource = searchVersionResource(bufSize, buf.get());
        if (versionResource == nullptr)
            return {};

        return extractVersionFromResource(bufSize, versionResource);
    }
    catch (const std::out_of_range&)
    {
        return {};
    }
}


using DWORD = uint32_t;
using WORD  = uint16_t;
using BYTE  = uint8_t;

#define _READ_BYTE(p)        (*reinterpret_cast<const unsigned char*>(p))
#define _READ_WORD(p)        (_READ_BYTE(p) | (_READ_BYTE(p + 1) << 8 ))
#define _READ_DWORD(p)       (_READ_WORD(p) | (_READ_WORD(p + 2) << 16))
static const char* _read_err_str = "Trying to read data past the buffer";

/*
static BYTE read_byte(size_t bufSize, const char* buf, size_t offset) {
    if (offset > bufSize)
        throw std::out_of_range(_read_err_str);
    return static_cast<BYTE>(_READ_BYTE(buf + offset));
}
*/
static WORD read_word(size_t bufSize, const char* buf, size_t offset) {
    if (offset > bufSize)
        throw std::out_of_range(_read_err_str);
    return static_cast<WORD>(_READ_WORD(buf + offset));
}
static DWORD read_dword(size_t bufSize, const char* buf, size_t offset) {
    if (offset > bufSize)
        throw std::out_of_range(_read_err_str);
    return static_cast<DWORD>(_READ_DWORD(buf + offset));
}

#undef _READ_BYTE
#undef _READ_WORD
#undef _READ_DWORD


static const char* searchVersionResource(size_t bufSize, const char* buf)
{
    //buf is a IMAGE_DOS_HEADER
    if (read_word(bufSize, buf, 0) != 0x5A4D) //MZ signature
        return nullptr;

    //pe is a IMAGE_NT_HEADERS32
    const char *pe = buf + read_word(bufSize, buf, 0x3C);
    if (read_word(bufSize, pe, 0) != 0x4550) //PE signature
        return nullptr;

    //coff is a IMAGE_FILE_HEADER
    const char *coff = pe + 4;
    WORD numSections = read_word(bufSize, coff, 2);
    WORD optHeaderSize = read_word(bufSize, coff, 16);
    if (numSections == 0 || optHeaderSize == 0)
        return nullptr;

    //optHeader is a IMAGE_OPTIONAL_HEADER32
    const char *optHeader = coff + 20;
    WORD magic = read_word(bufSize, optHeader, 0);
    if (magic != 0x10b && magic != 0x20b)
        return nullptr;

    //dataDir is an array of IMAGE_DATA_DIRECTORY
    const char* dataDir = optHeader + (magic == 0x10b ? 96 : 112);
    DWORD vaRes = read_dword(bufSize, dataDir, 8 * 2);

    //secTable is an array of IMAGE_SECTION_HEADER
    const char *secTable = optHeader + optHeaderSize;
    for (unsigned int i = 0; i < numSections; ++i)
    {
        //sec is a IMAGE_SECTION_HEADER*
        const char *sec = secTable + size_t(40u*i);
        char secName[9];
        memcpy(secName, sec, 8);
        secName[8] = '\0';

        if (strcmp(secName, ".rsrc") != 0)
            continue;
        DWORD vaSec = read_dword(bufSize, sec, 12);
        const char *raw = buf + read_dword(bufSize, sec, 20);
        const char *resSec = raw + (vaRes - vaSec);
        WORD numNamed = read_word(bufSize, resSec, 12);
        WORD numId = read_word(bufSize, resSec, 14);

        for (unsigned int j = 0; j < DWORD(numNamed) + numId; ++j)
        {
            //resSec is a IMAGE_RESOURCE_DIRECTORY followed by an array
            // of IMAGE_RESOURCE_DIRECTORY_ENTRY
            const char *res = resSec + 16 + 8 * j;
            DWORD name = read_dword(bufSize, res, 0);
            if (name != 16) //RT_VERSION
                continue;

            DWORD offs = read_dword(bufSize, res, 4);
            if ((offs & 0x80000000) == 0) //is a dir resource?
                return nullptr;

            //verDir is another IMAGE_RESOURCE_DIRECTORY and
            // IMAGE_RESOURCE_DIRECTORY_ENTRY array
            const char *verDir = resSec + (offs & 0x7FFFFFFF);
            numNamed = read_word(bufSize, verDir, 12);
            numId = read_word(bufSize, verDir, 14);
            if (numNamed == 0 && numId == 0)
                return nullptr;

            res = verDir + 16;
            offs = read_dword(bufSize, res, 4);
            if ((offs & 0x80000000) == 0) //is a dir resource?
                return nullptr;

            //and yet another IMAGE_RESOURCE_DIRECTORY, etc.
            verDir = resSec + (offs & 0x7FFFFFFF);
            numNamed = read_word(bufSize, verDir, 12);
            numId = read_word(bufSize, verDir, 14);
            if (numNamed == 0 && numId == 0)
                return nullptr;

            res = verDir + 16;
            offs = read_dword(bufSize, res, 4);
            if ((offs & 0x80000000) != 0) //is a dir resource?
                return nullptr;

            verDir = resSec + offs;
            DWORD verVa = read_dword(bufSize, verDir, 0);
            const char *verPtr = raw + (verVa - vaSec);
            return verPtr;
        }
        return nullptr;
    }
    return nullptr;
}


static std::vector<int> extractVersionFromResource(size_t bufSize, const char* versionResource)
{
#define PAD(x) (((x) + 3) & 0xFFFFFFFC)
    size_t offs = 0;
    WORD len = 0;
    do
    {
        offs = PAD(offs);
        len = read_word(bufSize, versionResource, offs);
        offs += 2;
        WORD valLen = read_word(bufSize, versionResource, offs);
        offs += 2;
        WORD type = read_word(bufSize, versionResource, offs);
        offs += 2;

        // Lazy UTF-16 to ASCII conversion (knowing that there aren't unicode characters)
        char info[200]{};
        for (int i = 0; i < 200; ++i)
        {
            WORD c = read_word(bufSize, versionResource, offs);
            offs += 2;

            info[i] = (char)c;
            if (!c)
                break;
        }

        offs = PAD(offs);

        if (type == 0)
        {
            if (strcmp(info, "VS_VERSION_INFO") == 0)
            {
                //fixed is a VS_FIXEDFILEINFO struct
                const char* fixed = versionResource + offs;
                WORD fileA = read_word(bufSize, fixed, 10);
                WORD fileB = read_word(bufSize, fixed, 8);
                WORD fileC = read_word(bufSize, fixed, 14);
                WORD fileD = read_word(bufSize, fixed, 12);
                /*
                WORD prodA = read_word(bufSize, fixed, 18);
                WORD prodB = read_word(bufSize, fixed, 16);
                WORD prodC = read_word(bufSize, fixed, 22);
                WORD prodD = read_word(bufSize, fixed, 20);
                */
                //printf("\tFile: %d.%d.%d.%d\n", fileA, fileB, fileC, fileD);
                //printf("\tProd: %d.%d.%d.%d\n", prodA, prodB, prodC, prodD);

                std::vector<int> ret = { fileA, fileB, fileC, fileD };
                return ret;
            }
            offs += valLen;
        }
        /*
        else //TEXT
        {
            char value[200]{};
            for (i = 0; i < valLen; ++i)
            {
                WORD c = read_word(bufSize, versionResource + offs);
                offs += 2;
                value[i] = c;
            }
            value[i] = 0;
            printf("info <%s>: <%s>\n", info, value);
        }
        */
    } while (offs < len);

    return {};
#undef PAD
}
