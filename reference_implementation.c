#include "reference_implementation.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define EXPANSION_FACTOR 3

#define SECURITY_MARGIN_FOR_LEMMA_1_BITS 256

unsigned char *DERIVED_CRS = "KDF_DERIVE";
unsigned char *INITIAL_INPUT_BLOCKS_PREFIX = "KDF";

#define SHA256_DIGEST_SIZE_BYTES (EVP_MD_size(EVP_sha256()))
#define SHA256_BLOCK_SIZE_BYTES 64

#define BYTES_TO_BITS 8

void derive_key(char key_index, const unsigned char *key, int key_len,
  const unsigned char *salt, int salt_len, unsigned char *output,
  unsigned int *md_len)
{
// k1_derived = H.hmac(k1, b'1' + DERIVED_CRS + salt)
  assert(key_index  == '1' || key_index == '2');
  HMAC_CTX *hmac_ctx = HMAC_CTX_new();
  HMAC_Init_ex(hmac_ctx, key, key_len, EVP_sha256(), NULL);
  HMAC_Update(hmac_ctx, &key_index, 1);
  HMAC_Update(hmac_ctx, DERIVED_CRS, strlen(DERIVED_CRS));
  HMAC_Update(hmac_ctx, salt, salt_len);
  HMAC_Final(hmac_ctx, output, md_len);
  HMAC_CTX_free(hmac_ctx);
}

unsigned char initial_input_blocks[EXPANSION_FACTOR][SHA256_BLOCK_SIZE_BYTES];
bool initialized_initial_input_blocks = false;

char int_to_char(int i)
{
  assert(0 <= i && i <= 9);
  return '0' + i;
}

void initialize_initial_input_blocks()
{
  // PREFIX + (block_num_as_char * (message_block_size - len(PREFIX)))
  for (int i = 0; i < EXPANSION_FACTOR; i++) {
    strcpy(initial_input_blocks[i], INITIAL_INPUT_BLOCKS_PREFIX);
    memset(initial_input_blocks[i] + strlen(INITIAL_INPUT_BLOCKS_PREFIX),
      int_to_char(i),
      SHA256_BLOCK_SIZE_BYTES - strlen(INITIAL_INPUT_BLOCKS_PREFIX));
  }
  initialized_initial_input_blocks = true;
}

void init()
{
  assert(SHA256_BLOCK_SIZE_BYTES == EVP_MD_block_size(EVP_sha256()));
  initialize_initial_input_blocks();
}

int min(int a, int b)
{
  if (a < b) {
    return a;
  }
  return b;
}

void hmac_on_expanded_key(const unsigned char *hmac_key, int hmac_key_len,
  char hmac_key_index, const unsigned char *key_to_expand,
  int key_to_expand_len, unsigned char *output, unsigned int *md_len)
{
  assert(hmac_key_index  == '1' || hmac_key_index == '2');
  int hash_block_size_bytes = SHA256_BLOCK_SIZE_BYTES;
  HMAC_CTX *hmac_ctx = HMAC_CTX_new();
  HMAC_Init_ex(hmac_ctx, hmac_key, hmac_key_len, EVP_sha256(), NULL);
  HMAC_Update(hmac_ctx, &hmac_key_index, 1);
  for (int j = 0; j < key_to_expand_len; j += hash_block_size_bytes) {
    for (int i = 0; i < EXPANSION_FACTOR; i++) {
      unsigned char inner_hash[SHA256_DIGEST_SIZE_BYTES];
      SHA256_CTX c;
      SHA256_Init(&c);
      SHA256_Update(&c, initial_input_blocks[i], hash_block_size_bytes);
      SHA256_Update(&c, key_to_expand + j,
        min(key_to_expand_len - j, hash_block_size_bytes));
      SHA256_Final(inner_hash, &c);
      HMAC_Update(hmac_ctx, inner_hash, SHA256_DIGEST_SIZE_BYTES);
    }
  }
  HMAC_Final(hmac_ctx, output, md_len);
  HMAC_CTX_free(hmac_ctx);
}

void xor_buffers(int len, const unsigned char *buffer1,
  const unsigned char *buffer2, unsigned char *output)
{
  for (int i = 0; i < len; i++) {
    output[i] = buffer1[i] ^ buffer2[i];
  }
}

void combine_keys(const unsigned char *k1, int k1_len, const unsigned char *k2,
  int k2_len, const unsigned char *salt, int salt_len, unsigned char *output)
{
  assert(initialized_initial_input_blocks);
  int k1_len_bits = k1_len * BYTES_TO_BITS;
  int k2_len_bits = k2_len * BYTES_TO_BITS;
  int sha256_digest_size_bits = SHA256_DIGEST_SIZE_BYTES * BYTES_TO_BITS;
  assert(sha256_digest_size_bits * EXPANSION_FACTOR >= SECURITY_MARGIN_FOR_LEMMA_1_BITS + k1_len_bits + k2_len_bits);

  unsigned char k1_derived[SHA256_DIGEST_SIZE_BYTES];
  unsigned char k2_derived[SHA256_DIGEST_SIZE_BYTES];
  unsigned int md_len;
  derive_key('1', k1, k1_len, salt, salt_len, k1_derived, &md_len);
  derive_key('2', k2, k2_len, salt, salt_len, k2_derived, &md_len);

  unsigned char side1[SHA256_DIGEST_SIZE_BYTES];
  hmac_on_expanded_key(k1_derived, SHA256_DIGEST_SIZE_BYTES, '1', k2, k2_len,
    side1, &md_len);

  unsigned char side2[SHA256_DIGEST_SIZE_BYTES];
  hmac_on_expanded_key(k2_derived, SHA256_DIGEST_SIZE_BYTES, '2', k1, k1_len,
    side2, &md_len);

  unsigned char xor_of_both_sides[SHA256_DIGEST_SIZE_BYTES];
  xor_buffers(SHA256_DIGEST_SIZE_BYTES, side1, side2, xor_of_both_sides);

  SHA256(xor_of_both_sides, md_len, output);
}
