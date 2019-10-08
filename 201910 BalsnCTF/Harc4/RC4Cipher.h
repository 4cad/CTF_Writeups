#pragma once

class RC4Cipher
{
public:
	void Initialize(unsigned char* key, int keylen);
	void Encrypt(unsigned char* block, int len);

private:
	unsigned char state[256];
	int x;
	int y;
};