#ifndef REFERENCE_IMPLEMENTATION_H
#define REFERENCE_IMPLEMENTATION_H

// This function is exposed for testing purposes only.
void derive_key(char key_index, const unsigned char *key, int key_len,
  const unsigned char *salt, int salt_len, unsigned char *output,
  unsigned int *md_len);

void init();

void combine_keys(const unsigned char *k1, int k1_len, const unsigned char *k2,
  int k2_len, const unsigned char *salt, int salt_len, unsigned char *output);

#endif
