#include "common.hpp"
#include "apis.hpp"

#pragma comment(linker, "/ENTRY:entry")

int entry(const PPEB peb)
{
    auto status = initialize_api_hashing();

    return 0;
}
