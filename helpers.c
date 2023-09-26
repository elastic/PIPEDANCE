#include "helpers.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

bool h_does_file_exist(const char* path)
{
    WIN32_FIND_DATAA data = { 0 };
    HANDLE handle = INVALID_HANDLE_VALUE;
    bool result = false;

    handle = FindFirstFileA(path, &data);
    result = INVALID_HANDLE_VALUE != handle;
    CloseHandle(handle);

    return result;
}

__declspec(noreturn) void h_error(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    printf("Error: ");
    vprintf(format, args);
    printf(". GLE=%d\n", GetLastError());

    va_end(args);

    exit(1);
}

void h_get_user_dword(const char* message, uint32_t* input)
{
    assert(message);
    assert(input);

    while (true)
    {
        printf(message);

        if (!scanf_s("%d", input))
        {
            printf("Failed to read dword, try again.\n");

            while (getchar() != '\n');
        }
        else
            break;
    }
}

void h_get_user_string(const char* message, char* input, size_t size)
{
    assert(message);
    assert(input);
    assert(size);

    while (true)
    {
        printf(message);

        if (!scanf_s(" %[^\n]", input, size))
        {
            printf("Failed to read string, try again.\n");

            while (getchar() != '\n');
        }
        else
            break;
    }
}

void h_get_wide_user_string(const wchar_t* message, wchar_t* input, size_t size)
{
    assert(message);
    assert(input);
    assert(size);

    while (true)
    {
        wprintf(L"%ls", message);

        if (!wscanf_s(L" %[^\n]", input, size))
        {
            wprintf(L"Failed to read string, try again.\n");

            while (getchar() != L'\n');
        }
        else
            break;
    }
}

HANDLE h_open_pipe(const char* path)
{
    assert(path);

    HANDLE pipe = INVALID_HANDLE_VALUE;

    pipe = CreateFileA(path, FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0,
        NULL);
    if (INVALID_HANDLE_VALUE == pipe)
        h_error("Failed to open pipe %s\n", path);

    return pipe;
}

uint8_t* h_read_file(const char* filename, size_t* size)
{
    assert(filename);
    assert(size);

    HANDLE file = INVALID_HANDLE_VALUE;
    uint8_t* shellcode = NULL;
    uint32_t s = 0;

    file = CreateFileA(filename, FILE_READ_ACCESS, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == file)
        h_error("Failed to open the file %s\n", filename);

    s = (size_t)GetFileSize(file, NULL);
    if (INVALID_FILE_SIZE == s)
        h_error("Failed to read the file size\n");

    shellcode = (uint8_t*)calloc(1, s);
    if (!shellcode)
        h_error("Failed to allocate shellcode memory\n");

    if (!ReadFile(file, shellcode, s, NULL, NULL))
        h_error("Failed to read shellcode from file\n");

    CloseHandle(file);

    *size = s;
    return shellcode;
}

uint8_t* h_bytes_from_hexlified(const char* string, size_t* size)
{
    assert(string);
    assert(size);

    size_t string_length = 0;
    size_t s = 0;
    uint8_t* bytes = NULL;

    string_length = strlen(string);
    if (string_length % 2 != 0)
        h_error("String length is odd\n");

    s = string_length / 2;
    bytes = (uint8_t*)calloc(1, s);
    if (!bytes)
        h_error("Failed to allocate the shellcode buffer\n");

    for (size_t i = 0; i < string_length; i += 2)
    {
        char str[3] = { string[i], string[i + 1], '\x00' };
        bytes[i / 2] = (unsigned char)strtoul(str, NULL, 16);
    }

    *size = s;
    return bytes;
}