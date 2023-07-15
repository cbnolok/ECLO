#include "exeversion_winapi.h"

#pragma comment(lib, "version.lib")
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>


std::vector<int> ExeVersion_WinAPI::getExeVersion(std::string filePath)
{
    DWORD  verHandle = 0;
    UINT   size = 0;
    LPBYTE lpBuffer = nullptr;
    size_t lenVersionFile = filePath.length() + 1;
    LPWSTR szVersionFile = static_cast<LPWSTR>(calloc(lenVersionFile, sizeof(wchar_t)));
    
    size_t converted = 0;
    mbstowcs_s(&converted, static_cast<wchar_t*>(szVersionFile), lenVersionFile, filePath.c_str(), lenVersionFile);
    if (szVersionFile == nullptr)
        return {};

    DWORD verSize = GetFileVersionInfoSizeW(szVersionFile, &verHandle);
    if (verSize)
    {
        LPSTR verData = new char[verSize];

        // for these functions you need to add the linker flag -lversion
        if (GetFileVersionInfoW(szVersionFile, verHandle, verSize, verData))
        {
            if (VerQueryValueW(verData, L"\\", (VOID FAR * FAR*) & lpBuffer, &size))
            {
                if (size)
                {
                    VS_FIXEDFILEINFO* verInfo = reinterpret_cast<VS_FIXEDFILEINFO*>(lpBuffer);
                    if (verInfo->dwSignature == 0xfeef04bd)
                    {
                        std::vector<int> ver;
                        ver.resize(4);

                        // Doesn't matter if you are on 32 bit or 64 bit,
                        // DWORD is always 32 bits, so first two revision numbers
                        // come from dwFileVersionMS, last two come from dwFileVersionLS
                        ver[0] = (verInfo->dwFileVersionMS >> 16) & 0xffff;
                        ver[1] = (verInfo->dwFileVersionMS >> 0) & 0xffff;
                        ver[2] = (verInfo->dwFileVersionLS >> 16) & 0xffff;
                        ver[3] = (verInfo->dwFileVersionLS >> 0) & 0xffff;
                    }
                }
            }
        }
        delete[] verData;
    }

    free(static_cast<void*>(szVersionFile));
    return {};
}
