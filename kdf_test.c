#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>

#include "reference_implementation.h"

#define MAX_HASH_DIGEST_SIZE_BYTES (EVP_MAX_MD_SIZE)

void print_hex(const unsigned char *buffer, int len)
{
  for (int i = 0; i < len; i++) {
    printf("%02x", buffer[i]);
  }
  printf("\n");
}

void compare_hex(const unsigned char *buffer, char *hex_string)
{
  char current_char_in_hex[3];
  for (int i = 0; i < strlen(hex_string) / 2; i++) {
    sprintf(current_char_in_hex, "%02x", buffer[i]);
    assert(current_char_in_hex[0] == hex_string[2*i]);
    assert(current_char_in_hex[1] == hex_string[2*i + 1]);
  }
}

unsigned char *buffer_from_hex(const char *hex)
{
  int hex_len = strlen(hex);
  unsigned char *buffer = (unsigned char *)malloc(hex_len / 2);
  for (int hex_i = 0, buffer_i = 0; hex_i < hex_len; hex_i+=2, buffer_i++) {
    int temp;
    sscanf(hex + hex_i, "%2x", &temp);
    assert(temp < 256);
    buffer[buffer_i] = temp;
  }
  return buffer;
}

void test_derive_key()
{
  unsigned char *k1 = "k1";
  unsigned char *salt = "salt";
  unsigned char derived_key[MAX_HASH_DIGEST_SIZE_BYTES];
  unsigned int md_len;
  derive_key('1', k1, strlen(k1), salt, strlen(salt), derived_key, &md_len);
  compare_hex(derived_key,
    "780036a6d119471c9e355472222fde0ffba936a9e4f70fe65e1b5c45833f5d8b");
}

void test_combine_keys()
{
  unsigned char *k1 = "k1";
  unsigned char *k2 = "aaabbbbccccc";
  unsigned char *salt = "salt";
  unsigned char combined_key[MAX_HASH_DIGEST_SIZE_BYTES];
  combine_keys(k1, strlen(k1), k2, strlen(k2), salt, strlen(salt),
    combined_key);
  compare_hex(combined_key,
    "1b2241d8263a103a770233fa2538c398a77820af0287c15da8eef320af6432a4");
}

void test_combine_keys2()
{
  unsigned char *k1 = buffer_from_hex(
    "4861b701f579fb629a4719b7411ed541cdbb71aa9df3ce567856441c738372d7");
  unsigned char *k2 = buffer_from_hex(
    "a396e23f94a115207927659908c2f577472a8c226f0e3dd3ca4b0493cba5a0a9");
  unsigned char combined_key[MAX_HASH_DIGEST_SIZE_BYTES];
  combine_keys(k1, 32, k2, 32, NULL, 0, combined_key);
  compare_hex(combined_key,
    "f97aa8e39f9f8431a1289834f95d3dcd1251fb3af5dc4acc43a6a3cf2c1d62c9");
  free(k1);
  free(k2);
  return;
}

void main()
{
  test_derive_key();
  init();
  test_combine_keys();
  test_combine_keys2();
}
