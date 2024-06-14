#include <Windows.h>


int main() {

	MessageBoxW(nullptr, L"Hello, World!", L"Hello, World!", MB_OK);

	typedef decltype(&MessageBoxW) type_MessageBoxW;

	auto func_MessageBoxW = reinterpret_cast<type_MessageBoxW>(
		GetProcAddress(LoadLibraryW(L"USER32.DLL"), "MessageBoxW")
	);

	func_MessageBoxW(nullptr, L"Hello, World!", L"Hello, World!", MB_OK);

	return 0;
}