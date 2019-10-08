#pragma once

#define MAX_KEY_LENGTH 256

#include <map>
#include <set>

class RC4HashCollider
{
public:
	void FindCollision(unsigned char* targetKeystream, int targetKeystreamLength, unsigned char* iv, int ivLength);

	unsigned char* GetKeyBytes();
	int GetKeyLength();


	enum C {
		BYPASS_INDEX_CHECK = 1,
		BYPASS_VALUE_CHECK = 2,
		VALIDATE = BYPASS_INDEX_CHECK | BYPASS_VALUE_CHECK,
		DONT_VALIDATE = 0
	};


private:

	void NeutralizeIV(unsigned char* iv, int ivLength);
	void ReserveTargetOutputs(unsigned char* targetKeystream, int targetKeystreamLength);
	std::pair<int, int> FindY(std::map<int, int>& invariants, int currentX, int lastY, int outputIndex);
	void SetInvariantsRequiredForOutput(unsigned char* targetKeystream, int targetKeystreamLength);

	void ValidateParams();

	void ConstructKey();

	bool IsFreeIndex(int index);
	bool IsFreeValue(int value);
	void ConsumeIndex(int index, C flags = C::VALIDATE);
	void ConsumeValue(int value, C flags = C::VALIDATE);
	void ConsumeSlot(int index, int value, C flags = C::VALIDATE);

	unsigned char keyBuffer[MAX_KEY_LENGTH];
	int keyLength;


	// These are the states that are guaranteed to be set in the final key
	// For example, if invariants[3] == 5 then the generated key will make sure
	// that RC4Cipher.state[3] == 5 after it has been initialized
	std::map<int, int> invariants;

	// The set of indexes which have been reserved and cannot be used by later stages of the collision algorithm
	std::set<int> consumedIndexes;
	
	// The set of values which have been reserved and cannot be used by later stages of the collision algorithm
	std::set<int> consumedValues;

	// The indexes that will be used to cancel out the effect of the IV during key scheduling.
	std::map<int, int> shieldIndexes;

	// Whenever we need to output a specific byte, that byte's index is looked up in this map so we know what index needs to be pointed to
	std::map<unsigned char, int> targetKeystreamIndex;

	int lastByteBeforeIV;
};