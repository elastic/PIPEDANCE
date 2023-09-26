#include "rc4.h"

void swap(uint8_t *a, uint8_t *b) {
  uint8_t temp = *a;
  *a = *b;
  *b = temp;
}

void rc4(const uint8_t *key, size_t key_len, uint8_t *data, size_t data_len) {
  uint8_t S[256];
  uint32_t i = 0;
  uint32_t j = 0;
  uint32_t t = 0;
  uint32_t k = 0;

  for (i = 0; i < 256; i++) {
    S[i] = i;
  }

  for (i = j = 0; i < 256; i++) {
    j = (j + S[i] + key[i % key_len]) % 256;
    swap(&S[i], &S[j]);
  }

  for (i = j = t = 0; t < data_len; t++) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;
    swap(&S[i], &S[j]);
    k = S[(S[i] + S[j]) % 256];
    data[t] ^= k;
  }
}
