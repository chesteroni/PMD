#pragma once
#include <Windows.h>
#include <winternl.h>
#include <type_traits>

#define TOKENIZEA(x) #x
#define TOKENIZEW(x) L#x
#define CONCAT(x, y) x##y

////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////

template <typename T>
concept Hashable = std::is_trivial_v<T>;

template <typename T>
concept CharOrWChar = std::is_same_v<T, char> || std::is_same_v<T, wchar_t>;

template <CharOrWChar T> constexpr T to_uppercase(T c)
{
    if (c >= 'a' && c <= 'z')
    {
        return c - 32;
    }

    return c;
}

template <typename T> T rva2_va(void* base, const unsigned long rva)
{
    return reinterpret_cast<T>(reinterpret_cast<unsigned long long>(base) + rva);
}

////////////////////////////////////////////////////////////////
// Hashing Algorithm
////////////////////////////////////////////////////////////////

template <bool Uppercase = false, CharOrWChar T> constexpr auto hash_string_fnv1a(const T* buffer)
{
    ULONG hash = 0x811c9dc5;
    while (*buffer)
    {
        T c{};
        if constexpr (Uppercase)
        {
            c = to_uppercase(*buffer);
        }
        else
        {
            c = *buffer;
        }

        hash ^= c;
        hash *= 0x01000193;

        ++buffer;
    }

    return hash;
}

////////////////////////////////////////////////////////////////
// Hashing Macros
////////////////////////////////////////////////////////////////

#define HASHING_ALGORITHM    hash_string_fnv1a
#define HASH_STRINGA(string) HASHING_ALGORITHM(TOKENIZEA(string))
#define HASH_STRINGW(string) HASHING_ALGORITHM(TOKENIZEW(string))
#define HASH_STRINGA(string) HASHING_ALGORITHM(TOKENIZEA(string))
#define HASH_STRINGW(string) HASHING_ALGORITHM(TOKENIZEW(string))

#define DEFINE_HASH_STRINGA(string)                               \
    constexpr auto CONCAT(hash__, string) = HASH_STRINGA(string); \
    static_assert(CONCAT(hash__, string) == HASH_STRINGA(string), "Must be evaluated at compile time");

#define DEFINE_HASH_STRINGW(string)                               \
    constexpr auto CONCAT(hash__, string) = HASH_STRINGW(string); \
    static_assert(CONCAT(hash__, string) == HASH_STRINGW(string), "Must be evaluated at compile time");

#define DEFINE_FUNCTION(function) typedef decltype(&function) CONCAT(type__, function);

#define HASHED_FUNCTION(function) DEFINE_HASH_STRINGA(function) DEFINE_FUNCTION(function)

#define API(function, dll)                                                   \
    reinterpret_cast<CONCAT(type__, function)>(                              \
        get_proc_address_hash(CONCAT(hash__, function), CONCAT(hash__, dll)) \
    )

#define DLL_NAME(dll)   L#dll L".DLL"
#define DEFINE_DLL(dll) constexpr auto CONCAT(hash__, dll) = HASHING_ALGORITHM(DLL_NAME(dll));

////////////////////////////////////////////////////////////////
// UPDATE ME WITH FUNCTIONS/LIBRARIES TO USE
////////////////////////////////////////////////////////////////

HASHED_FUNCTION(GetProcAddress) // Required.
HASHED_FUNCTION(LoadLibraryW)

DEFINE_DLL(NTDLL)
DEFINE_DLL(KERNEL32)

// UPDATE WITH DLLS REQUIRED AT RUNTIME
static constexpr const wchar_t* required_dlls[] = {
    L"NTDLL.DLL",
    L"KERNEL32.DLL",
};

////////////////////////////////////////////////////////////////
// API Resolution
////////////////////////////////////////////////////////////////

template <Hashable T> FORCEINLINE PVOID get_module_handle(const T target_hash)
{
    const LIST_ENTRY* head = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY*       next = head->Flink;

    while (next != head)
    {
        const auto entry    = CONTAINING_RECORD(next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        const auto dll_name = reinterpret_cast<UNICODE_STRING*>(
            reinterpret_cast<BYTE*>(&entry->FullDllName) + sizeof(UNICODE_STRING)
        );

        auto dll_name_buffer = reinterpret_cast<wchar_t*>(dll_name->Buffer);

        auto dll_name_hash = HASHING_ALGORITHM<true>(dll_name_buffer);

        if (dll_name_hash == target_hash)
        {
            return entry->DllBase;
        }
        next = next->Flink;
    }

    return nullptr;
}

template <Hashable T> FORCEINLINE void* get_proc_address_hash(T function_hash, T library_hash)
{
    // 1. Get the DLL handle from the library hash
    auto dll_base = get_module_handle(library_hash);
    if (!dll_base) [[unlikely]]
        return nullptr;

    // 2. Get the function address from the function hash
    const auto dos     = static_cast<PIMAGE_DOS_HEADER>(dll_base);
    const auto nt      = rva2_va<PIMAGE_NT_HEADERS>(dll_base, dos->e_lfanew);
    const auto exports = rva2_va<PIMAGE_EXPORT_DIRECTORY>(
        dll_base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );
    const auto optional = &nt->OptionalHeader;

    if (exports->AddressOfNames == 0) [[unlikely]]
        return nullptr;

    const auto ordinals  = rva2_va<PWORD>(dll_base, exports->AddressOfNameOrdinals);
    const auto names     = rva2_va<PDWORD>(dll_base, exports->AddressOfNames);
    const auto functions = rva2_va<PDWORD>(dll_base, exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++)
    {
        const auto name = rva2_va<LPSTR>(dll_base, names[i]);
        const auto hash = HASHING_ALGORITHM(name);

        if (hash == function_hash)
        {
            PVOID function_address = rva2_va<BYTE*>(dll_base, functions[ordinals[i]]);

            // 3. Handle forwarded functions
            const auto optional_start = rva2_va<PVOID>(dll_base, optional->DataDirectory[0].VirtualAddress);
            const auto optional_end   = rva2_va<PVOID>(optional_start, optional->DataDirectory[0].Size);
            if (function_address >= optional_start && function_address < optional_end)
            {
                function_address = (void*)API(GetProcAddress, KERNEL32)(static_cast<HMODULE>(dll_base), name);
            }
            return function_address;
        }
    }

    return nullptr;
}

BOOL initialize_api_hashing()
{
    auto status = false;
    for (auto& dll : required_dlls)
    {
        auto addr = API(LoadLibraryW, KERNEL32)(dll);
        if (status = addr; !status) [[unlikely]]
            return status;
    }

    return status;
}