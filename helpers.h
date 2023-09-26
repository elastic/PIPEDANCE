#ifndef HELPERS_H
#define HELPERS_H

#include <Windows.h>

#include <stdbool.h>
#include <stdint.h>

bool h_does_file_exist(const char* path);
__declspec(noreturn) void h_error(const char* format, ...);
void h_get_user_dword(const char* message, uint32_t* input);
void h_get_user_string(const char* message, char* input, size_t size);
void h_get_wide_user_string(const wchar_t* message, wchar_t* input, size_t size);
HANDLE h_open_pipe(const char* path);
uint8_t* h_read_file(const char* filename, size_t* size);
uint8_t* h_bytes_from_hexlified(const char* string, size_t* size);

#endif // !HELPERS_H