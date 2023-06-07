#pragma once
#include <cstdint>
#include <CoreWindow.h>

#include "nt.hpp"

size_t _strlen(const char* str);
size_t _wstrlen(const wchar_t* str);
char _lowercase(char c);
bool _wstr_icmp_str(const wchar_t* s1, const char* s2);

uint8_t* get_module_base(const char* name);
void* resolve_import(const char* dll_name, const char* import_name);

PEB64* get_peb();

typedef bool(__fastcall* fn_virtual_protect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef void* (__fastcall* fn_load_library)(const char* dll_name);
typedef void* (__fastcall* fn_get_proc_address)(void* lib, const char* import_name);

DWORD __fastcall jump_to_original();
void __fastcall resolve_descriptor_list(fn_virtual_protect protect, fn_load_library load_library, fn_get_proc_address get_proc_address);