#include "reference_implementation.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define KEY_LENGTH_BYTES 32
#define DIGEST_LENGTH_BYTES 32

#define NUM_OF_COMBINE_KEYS_CALLS_TO_MEASURE (200 * 1000)
#define NUM_OF_HKDF_EXTRACT_CALLS_TO_MEASURE (1000 * 1000)

#define MICROSECONDS_PER_SEC (1000 * 1000)

void fill_buffer_with_random(unsigned char *buffer, int len)
{
  FILE *f = fopen("/dev/urandom", "rb");
  int bytes_read = fread(buffer, sizeof(unsigned char), len, f);
  fclose(f);
}

void print_benchmark_results(const char *function_name, long num_of_calls,
                             double time_elapsed)
{
  double calls_per_second = num_of_calls / time_elapsed;
  double microseconds_per_call = ((double)MICROSECONDS_PER_SEC) / calls_per_second;
  printf("Did %ld calls to %s()\tin %.2f seconds, "
         "speed is %.2f calls/second, "
         "average is %.2f microseconds/call.\n",
         num_of_calls, function_name, time_elapsed, calls_per_second,
         microseconds_per_call);
}

void benchmark_combine_keys()
{
  assert(KEY_LENGTH_BYTES == DIGEST_LENGTH_BYTES);
  init();
  int buffer_len = KEY_LENGTH_BYTES;
  unsigned char buffer1[buffer_len], buffer2[buffer_len], buffer3[buffer_len];
  fill_buffer_with_random(buffer1, buffer_len);
  fill_buffer_with_random(buffer2, buffer_len);
  fill_buffer_with_random(buffer3, buffer_len);
  unsigned char salt[DIGEST_LENGTH_BYTES] = {0};

  clock_t start = clock();
  int i;
  for (i = 0; i < NUM_OF_COMBINE_KEYS_CALLS_TO_MEASURE / 3; i++) {
    combine_keys(buffer1, KEY_LENGTH_BYTES,
                 buffer2, KEY_LENGTH_BYTES,
                 salt,    DIGEST_LENGTH_BYTES,
                 buffer3);

    combine_keys(buffer2, KEY_LENGTH_BYTES,
                 buffer3, KEY_LENGTH_BYTES,
                 salt, DIGEST_LENGTH_BYTES,
                 buffer1);

    combine_keys(buffer3, KEY_LENGTH_BYTES,
                 buffer1, KEY_LENGTH_BYTES,
                 salt, DIGEST_LENGTH_BYTES,
                 buffer2);
  }
  clock_t end = clock();
  double time_elapsed = (double)(end - start) / CLOCKS_PER_SEC;
  int num_of_calls = 3 * i;
  print_benchmark_results("combine_keys", num_of_calls, time_elapsed);
}

void benchmark_hkdf_extract()
{
  unsigned char salt[DIGEST_LENGTH_BYTES] = {0};
  int buffer_len = DIGEST_LENGTH_BYTES + 2 * KEY_LENGTH_BYTES;
  unsigned char buffer[buffer_len];
  fill_buffer_with_random(buffer, buffer_len);
  int md_len;
  clock_t start = clock();
  int i;
  for (i = 0; i < NUM_OF_HKDF_EXTRACT_CALLS_TO_MEASURE / 2; i++) {
    HMAC(EVP_sha256(), salt, DIGEST_LENGTH_BYTES, buffer, 2 * KEY_LENGTH_BYTES,
         buffer + 2 * KEY_LENGTH_BYTES, &md_len);

    HMAC(EVP_sha256(), salt, DIGEST_LENGTH_BYTES, buffer + KEY_LENGTH_BYTES,
         2 * KEY_LENGTH_BYTES, buffer, &md_len);
  }
  clock_t end = clock();
  double time_elapsed = (double)(end - start) / CLOCKS_PER_SEC;
  int num_of_calls = 2 * i;
  print_benchmark_results("hkdf_extract", num_of_calls, time_elapsed);
}

void main()
{
  printf("Benchmarking combine_keys():\n");
  benchmark_combine_keys();

  printf("Benchmarking hkdf_extract():\n");
  benchmark_hkdf_extract();
}
