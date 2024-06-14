#include "common.hpp"
#include "apis.hpp"

#pragma comment(linker,"/ENTRY:entry")

int entry(const PPEB peb) {
	auto status = initialize_api_hashing();

	API(MessageBoxW, USER32)(nullptr, L"Hello, World!",
		L"Hello, World!", MB_OK);

	return 0;
}
