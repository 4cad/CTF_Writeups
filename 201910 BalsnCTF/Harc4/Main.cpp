#include <stdlib.h>
#include <vector>
#include <string>
#include <stdexcept>

#include <map>
#include <set>
#include <vector>

#include "RC4Cipher.h"
#include "RC4HashCollider.h"
#include "Utils.h"

#define IV_START_INDEX 256-32

int main(int argc, char* argv[])
{
	bool xorTargetAgainstIv = false;
	std::string targetStr;
	std::string ivStr;
	if (argc == 3 || argc == 4)
	{
		HexToString(argv[1], targetStr);
		HexToString(argv[2], ivStr);
		if (argc == 4 && strcmp(argv[3], "CTF") == 0)
		{
			xorTargetAgainstIv = true;
		}
	}
	else
	{
		printf("Usage: %s TARGET_KEYSTREAM IV", argv[0]);
		return 1;
	}

	unsigned char* target = (unsigned char*)targetStr.c_str();
	unsigned char* iv = (unsigned char*)ivStr.c_str();

	if (xorTargetAgainstIv)
	{
		for (int i = 0; i < 32; i++)
		{
			target[i] ^= iv[i];
		}
	}

	PrintHex("target", target, 32);
	PrintHex("iv", iv, 32);

	unsigned char key[256];
	std::fill(key, key + sizeof(key), 0);

	RC4HashCollider collider;
	collider.FindCollision(target, targetStr.size(), iv, ivStr.size());
	for (int i = 0; i < collider.GetKeyLength(); i++) key[i] = collider.GetKeyBytes()[i];

	// This is meant to mirror what the python code at the server will do by appending the IV to the key
	for (int i = 0; i < 32; i++) key[IV_START_INDEX + i] = iv[i];

	RC4Cipher cipher;
	cipher.Initialize(key, sizeof(key));

	unsigned char keystream[32];
	std::fill(keystream, keystream + sizeof(keystream), 0);

	cipher.Encrypt(keystream, targetStr.size());


	printf("\n");

	PrintHex("keystream_guess", keystream, targetStr.size());
	PrintHex("keystream_expct", target, targetStr.size());
	printf("memcmp(keystream, target_keystream, NUM_OUTPUT_BYTES) == %d\n", memcmp(keystream, target, targetStr.size()));
	printf("==================================\n");
	PrintHex("colliding_key=", key, 256 - 32);

}