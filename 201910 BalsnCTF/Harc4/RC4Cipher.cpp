#include <algorithm>

#include "RC4Cipher.h"

void RC4Cipher::Encrypt(unsigned char* block, int len)
{
	for (int i = 0; i < len; i++)
	{
		x = (x + 1) % 256;
		y = (y + state[x]) % 256;

		std::swap(state[x], state[y]);

		int xorIndex = (state[x] + state[y]) % 256;
		block[i] ^= state[xorIndex];
	}
}

void RC4Cipher::Initialize(unsigned char* key, int keylen)
{
	for (int i = 0; i < 256; i++) state[i] = i;	
	int keyIndex = 0;
	y = 0;

	for (int x = 0; x < 256; x++)
	{
		y = (y + state[x] + key[keyIndex]) % 256;
		std::swap(state[x], state[y]);

		keyIndex = (keyIndex + 1) % keylen;
	}

	x = 0;
	y = 0;
}
