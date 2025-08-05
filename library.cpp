//  基于https://github.com/namazso/MagicSigner 修改部分代码

#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <Wincrypt.h>
#include "detours.h"

HINSTANCE get_original_dll() {
  static HINSTANCE p{};
  if (!p)
    p = LoadLibraryExA("XmlLite.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  return p;
}

template <typename Fn>
Fn get_original(const char* name) {
  return (Fn)GetProcAddress(get_original_dll(), name);
}

using fnCreateXmlReader = HRESULT(WINAPI*)(REFIID riid, void** ppvObject, IMalloc* pMalloc);
using fnCreateXmlReaderInputWithEncodingCodePage = HRESULT(WINAPI*)(IUnknown* pInputStream, IMalloc* pMalloc, UINT nEncodingCodePage, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput);
using fnCreateXmlReaderInputWithEncodingName = HRESULT(WINAPI*)(IUnknown* pInputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput);
using fnCreateXmlWriter = HRESULT(WINAPI*)(REFIID riid, void** ppvObject, IMalloc* pMalloc);
using fnCreateXmlWriterOutputWithEncodingCodePage = HRESULT(WINAPI*)(IUnknown* pOutputStream, IMalloc* pMalloc, UINT nEncodingCodePage, struct IXmlWriterOutput** ppOutput);
using fnCreateXmlWriterOutputWithEncodingName = HRESULT(WINAPI*)(IUnknown* pOutputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, struct IXmlWriterOutput** ppOutput);

EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlReader(REFIID riid, void** ppvObject, IMalloc* pMalloc) {
  return get_original<fnCreateXmlReader>("CreateXmlReader")(riid, ppvObject, pMalloc);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlReaderInputWithEncodingCodePage(IUnknown* pInputStream, IMalloc* pMalloc, UINT nEncodingCodePage, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput) {
  return get_original<fnCreateXmlReaderInputWithEncodingCodePage>("CreateXmlReaderInputWithEncodingCodePage")(pInputStream, pMalloc, nEncodingCodePage, fEncodingHint, pwszBaseUri, ppInput);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlReaderInputWithEncodingName(IUnknown* pInputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, BOOL fEncodingHint, LPCWSTR pwszBaseUri, struct IXmlReaderInput** ppInput) {
  return get_original<fnCreateXmlReaderInputWithEncodingName>("CreateXmlReaderInputWithEncodingName")(pInputStream, pMalloc, pwszEncodingName, fEncodingHint, pwszBaseUri, ppInput);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlWriter(REFIID riid, void** ppvObject, IMalloc* pMalloc) {
  return get_original<fnCreateXmlWriter>("CreateXmlWriter")(riid, ppvObject, pMalloc);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlWriterOutputWithEncodingCodePage(IUnknown* pOutputStream, IMalloc* pMalloc, UINT nEncodingCodePage, struct IXmlWriterOutput** ppOutput) {
  return get_original<fnCreateXmlWriterOutputWithEncodingCodePage>("CreateXmlWriterOutputWithEncodingCodePage")(pOutputStream, pMalloc, nEncodingCodePage, ppOutput);
}
EXTERN_C __declspec(dllexport) HRESULT STDAPICALLTYPE CreateXmlWriterOutputWithEncodingName(IUnknown* pOutputStream, IMalloc* pMalloc, LPCWSTR pwszEncodingName, struct IXmlWriterOutput** ppOutput) {
  return get_original<fnCreateXmlWriterOutputWithEncodingName>("CreateXmlWriterOutputWithEncodingName")(pOutputStream, pMalloc, pwszEncodingName, ppOutput);
}


// Resolve jump instructions and return the real function entry
void* follow_jumps(void* address) {
    uint8_t* ptr = reinterpret_cast<uint8_t*>(address);
    int depth = 0;
    while (depth++ < 16) {
        __try {
            // JMP rel8: EB xx
            if (ptr[0] == 0xEB) {
                int8_t offset = *(int8_t*)&ptr[1];
                ptr += 2 + offset;
                continue;
            }
            // JMP rel32: E9 xx xx xx xx
            if (ptr[0] == 0xE9) {
                int32_t offset = *reinterpret_cast<int32_t*>(&ptr[1]);
                ptr += 5 + offset;
                continue;
            }
            // JMP [RIP + rel32]: FF 25 xx xx xx xx (commonly seen in x64 IAT)
            if (ptr[0] == 0xFF && ptr[1] == 0x25) {
                int32_t offset = *reinterpret_cast<int32_t*>(&ptr[2]);
                uint8_t** target = reinterpret_cast<uint8_t**>(ptr + 6 + offset);
                ptr = *target;
                continue;
            }
            // JMP qword ptr [RIP + rel32]: 48 FF 25 xx xx xx xx (more robust x64 support)
            if (ptr[0] == 0x48 && ptr[1] == 0xFF && ptr[2] == 0x25) {
                int32_t offset = *reinterpret_cast<int32_t*>(&ptr[3]);
                uint8_t** target = reinterpret_cast<uint8_t**>(ptr + 7 + offset);
                ptr = *target;
                continue;
            }
            // MOV RAX, imm64; JMP RAX pattern: 48 B8 xx..xx; FF E0 (used in some x64 trampolines)
            if (ptr[0] == 0x48 && ptr[1] == 0xB8 && ptr[10] == 0xFF && ptr[11] == 0xE0) {
                uint64_t target = *reinterpret_cast<uint64_t*>(&ptr[2]);
                ptr = reinterpret_cast<uint8_t*>(target);
                continue;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // On error, return current address
            break;
        }
        // Not a jump instruction, stop resolving
        break;
    }
    return ptr;
}

// resolve_entry template
template<typename T>
T resolve_entry(T fn) {
#if defined(_WIN64)
    return reinterpret_cast<T>(follow_jumps(reinterpret_cast<void*>(fn)));
#else
    return fn;
#endif
}

static decltype(&CertVerifyTimeValidity) Real_CertVerifyTimeValidity = nullptr;
static decltype(&GetSystemTimeAsFileTime) Real_GetSystemTimeAsFileTime = nullptr;

LONG WINAPI Hook_CertVerifyTimeValidity(LPFILETIME, PCERT_INFO) {
    return 0; // always valid
}

VOID WINAPI Hook_GetSystemTimeAsFileTime(LPFILETIME lpTime) {
    *lpTime = {}; // zero out time
}

void initialize() {
    Real_CertVerifyTimeValidity = resolve_entry(CertVerifyTimeValidity);
    Real_GetSystemTimeAsFileTime = resolve_entry(GetSystemTimeAsFileTime);
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID*)&Real_CertVerifyTimeValidity, Hook_CertVerifyTimeValidity);
    DetourAttach((PVOID*)&Real_GetSystemTimeAsFileTime, Hook_GetSystemTimeAsFileTime);
    DetourTransactionCommit();
    //LONG status = DetourTransactionCommit();
    //printf("DetourTransactionCommit status: %ld\n", status);
}

void deinitialize() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach((PVOID*)&Real_CertVerifyTimeValidity, Hook_CertVerifyTimeValidity);
    DetourDetach((PVOID*)&Real_GetSystemTimeAsFileTime, Hook_GetSystemTimeAsFileTime);

    DetourTransactionCommit();
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        initialize();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        deinitialize();
    }
    return TRUE;
}
