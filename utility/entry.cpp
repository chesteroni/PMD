#include <Windows.h>
#include <winternl.h>
#include <cstdio>

template <typename T> T rva2_va(void* base, const unsigned long rva)
{
    return reinterpret_cast<T>(reinterpret_cast<unsigned long long>(base) + rva);
}

static bool ends_with(const wchar_t* string, const wchar_t* suffix)
{
    if (string == nullptr || suffix == nullptr)
        return false;

    const size_t str_len    = wcslen(string);
    const size_t suffix_len = wcslen(suffix);

    if (suffix_len > str_len)
        return true;

    return wcscmp(string + str_len - suffix_len, suffix) == 0;
}

template <typename callback>
void file_finder(const wchar_t* dir_root, const wchar_t* file_ext, callback file_callback)
{
    wchar_t*         current_path = NULL;
    WIN32_FIND_DATAW find_data    = {};
    HANDLE           find_file    = INVALID_HANDLE_VALUE;

    current_path = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32768 * sizeof(wchar_t));
    if (current_path == NULL)
        return;

    (void)lstrcpyW(current_path, dir_root);
    (void)lstrcatW(current_path, L"\\*");

    find_file = FindFirstFileW(current_path, &find_data);
    if (find_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    do
    {
        if (!lstrcmpW(find_data.cFileName, L".") || !lstrcmpW(find_data.cFileName, L".."))
            continue;

        (void)lstrcpyW(current_path, dir_root);
        (void)lstrcatW(current_path, L"\\");
        (void)lstrcatW(current_path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            file_finder(current_path, file_ext, file_callback);
        else if (ends_with(find_data.cFileName, file_ext))
            file_callback(current_path);
    } while (FindNextFileW(find_file, &find_data));

cleanup:
    if (current_path != NULL)
    {
        (void)HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, current_path);
    }
    if (find_file != INVALID_HANDLE_VALUE)
    {
        (void)FindClose(find_file);
    }
}

int main()
{
    file_finder(
        L"C:",
        L".dll",
        [](const wchar_t* file_path)
        {
            HANDLE                dll_handle      = INVALID_HANDLE_VALUE;
            HANDLE                dll_mapping     = INVALID_HANDLE_VALUE;
            HANDLE                mapped_dll_base = INVALID_HANDLE_VALUE;
            PIMAGE_DOS_HEADER     dos_header      = NULL;
            PIMAGE_NT_HEADERS     nt_headers      = NULL;
            PIMAGE_SECTION_HEADER section_header  = NULL;

            dll_handle = CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (dll_handle == INVALID_HANDLE_VALUE)
                goto cleanup;

            dll_mapping = CreateFileMappingA(dll_handle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
            if (dll_mapping == nullptr)
                goto cleanup;

            mapped_dll_base = MapViewOfFile(dll_mapping, FILE_MAP_READ, 0, 0, 0);
            if (mapped_dll_base == NULL)
                goto cleanup;

            dos_header = (PIMAGE_DOS_HEADER)mapped_dll_base;
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
                goto cleanup;

            nt_headers = rva2_va<PIMAGE_NT_HEADERS>(mapped_dll_base, dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
                goto cleanup;

            section_header = IMAGE_FIRST_SECTION(nt_headers);
            for (int j = 0; j < nt_headers->FileHeader.NumberOfSections; j++, section_header++)
            {
                if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE
                    && section_header->Characteristics & IMAGE_SCN_MEM_READ
                    && section_header->Characteristics & IMAGE_SCN_MEM_WRITE)
                {
                    printf("%s - 0x%x bytes\t%S\n", section_header->Name, section_header->SizeOfRawData, file_path);
                    break;
                }
            }

        cleanup:
            if (dll_handle)
                CloseHandle(dll_handle);
            if (dll_mapping)
                CloseHandle(dll_mapping);
            if (mapped_dll_base)
                UnmapViewOfFile(mapped_dll_base);
        }
    );
}