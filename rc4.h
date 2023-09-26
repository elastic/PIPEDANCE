#ifndef RC4_H
#define RC4_H

#include <stdint.h>

void rc4(const uint8_t *key, size_t key_len, uint8_t *data, size_t data_len);

#endif // !RC4_H