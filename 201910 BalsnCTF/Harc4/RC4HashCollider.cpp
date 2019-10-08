#include <algorithm>
#include <stdexcept>
#include <vector>

#include "RC4HashCollider.h"

void RC4HashCollider::FindCollision(unsigned char* targetKeystream, int targetKeystreamLength, unsigned char* iv, int ivLength)
{
	lastByteBeforeIV = MAX_KEY_LENGTH - ivLength - 1;
	keyLength = MAX_KEY_LENGTH - ivLength;
	std::fill(keyBuffer, keyBuffer + keyLength, 0);
	for (int i = 0; i < targetKeystreamLength; i++) ConsumeValue(targetKeystream[i]);
	for (int i = 1; i <= 32; i++) ConsumeIndex(i);

	NeutralizeIV(iv, ivLength);

	ReserveTargetOutputs(targetKeystream, targetKeystreamLength);
	SetInvariantsRequiredForOutput(targetKeystream, targetKeystreamLength);

	ConstructKey();
}

void RC4HashCollider::NeutralizeIV(unsigned char* iv, int ivLength)
{

	// We are going to use zero as the target for all of the swaps during key scheduling that we don't care about
	ConsumeValue(0);
	ConsumeIndex(0);

	// We neutralize the IV by making sure that it can only impact the indexes at 0, 64, 128, 196 because
	// it is convenient to implement in the short time of this CTF. Even though we do not control the IV bytes,
	// the only place the IV bytes are used is during the last 32 iterations of key scheduling and we can set up 
	// the last 32 slots to prevent the IV from changing any of the indexes that are needed
	ConsumeIndex(64);
	ConsumeIndex(128);
	ConsumeIndex(192);

	for (int i = 0; i < ivLength; i++)
	{
		int keyIndex = 256 - ivLength + i;
		ConsumeIndex(keyIndex);
		int iv_value = iv[i];

		// We need a value which when added to this IV byte, will be 0, 64, 128, 196 so that the IV's side effect is contained
		int neutralizer = (256 - iv_value) % 256;

		bool found = false;
		for (int j = 0; j < 4; j++)
		{
			int v = (neutralizer + 64 * j) % 256;
			if (32 < v && v < lastByteBeforeIV && consumedValues.count(v) == 0)
			{
				ConsumeIndex(v);
				ConsumeValue(v);
				shieldIndexes[v] = keyIndex;
				found = true;
				break;
			}
		}

		if (!found)
		{
			throw std::runtime_error("No shield available!");
		}
	}
}

void RC4HashCollider::ReserveTargetOutputs(unsigned char* targetKeystream, int targetKeystreamLength)
{
	for (int i = 0; i < targetKeystreamLength; i++)
	{
		unsigned char value = targetKeystream[i];
		if (targetKeystreamIndex.find(value) == targetKeystreamIndex.end())
		{
			int index = (45 + 5 * i) % 256;
			while (!IsFreeIndex(index))
			{
				index = (index + 3) % 256;
			}
			targetKeystreamIndex[value] = index;
			ConsumeSlot(index, value, C::BYPASS_VALUE_CHECK);
		}
	}
}

void RC4HashCollider::SetInvariantsRequiredForOutput(unsigned char *targetKeystream, int targetKeystreamLength)
{
	// x must be 1, 2, 3, .., 32
	// y is added to itself each time

	// x_1 = 1
	// y_1 = 0 + S[1] (before swap)

	// x_2 = 2
	// y_2 = S[1] + S[2] (before swap)

	// x_3 = 3
	// y_3 = S[1] + S[2] + S[3] (before swap)

	// We want all ys to be above 32 so they dont screw with the x's... so S[1] = 255
	// So the sequence S[1..32] determines the ys, as long as no y falls within that range.
	// Say s[2] = 244 and so forth, so it is basically y starts at 255 and works its way down

	std::vector<int> yValues;

	int y = 0;
	unsigned char state[256];
	for (int i = 0; i < 256; i++) state[i] = i;

	unsigned char* targetKeystreamByte = targetKeystream, * targetKeystreamEnd = targetKeystream + targetKeystreamLength;
	for (int x = 1; x <= 32 && targetKeystream != targetKeystreamEnd; x++, targetKeystreamByte++)
	{
		int indexToRead = targetKeystreamIndex[*targetKeystreamByte];

		// Find a xValue, yValue such that: 
		//    - xValue is an index that has is not in the LHS or RHS of an invariant
		//    - yValue is a value is not in the RHS of an invariant
		//    - xValue + yValue = indexToRead 

		// Since desiredY = y + xValue, we know that xValue = desiredY - y
		std::pair<int, int> values = FindY(invariants, x, y, indexToRead);
		int xValue = values.first;
		int yValue = values.second;

		y = (y + xValue) % 256;

		ConsumeSlot(y, yValue);
		ConsumeSlot(x, xValue, C::BYPASS_INDEX_CHECK);

		targetKeystream++;
	}
}

std::pair<int, int> RC4HashCollider::FindY(std::map<int, int>& invariants, int currentX, int lastY, int targetKeystreamIndex)
{
	for (int xValue = 33; xValue < 256; xValue++)
	{
		int newY = (lastY + xValue) % 256;
		int yValue = (targetKeystreamIndex - xValue + 512) % 256;

		if (newY != currentX && yValue != xValue && IsFreeValue(xValue) && IsFreeIndex(newY) && IsFreeValue(yValue))
		{
			return std::pair<int, int>(xValue, yValue);
		}
	}
	throw std::runtime_error("No y to be found!");
}

void RC4HashCollider::ConstructKey()
{
	ValidateParams();

	std::set<int> uselessIndexes;
	for (int i = 0; i < lastByteBeforeIV; i++)
	{
		bool isInvariant = invariants.find(i) != invariants.end();
		bool isShield = shieldIndexes.find(i) != shieldIndexes.end();
		if (!isInvariant && !isShield)
		{
			uselessIndexes.insert(i);
		}

		if (isInvariant && isShield)
		{
			throw std::runtime_error("Index cannot be shield and invariant!");
		}
	}

	// The rest of this method is a mutilated version of the real RC4 key scheduling algorithm,
	// which instead of taking a key as input produces a key as output so that each byte of the
	// key results in the correct side effect
	unsigned char state[256];
	for (int i = 0; i < 256; i++) state[i] = i;

	int y = 0;
	for (int x = 0; x < lastByteBeforeIV + 1; x++)
	{
		register int t;

		int swapTarget = -1;
		auto iter = invariants.find(x);
		if (iter != invariants.end())
		{
			int targetValue = iter->second;
			for (int j = 0; j < 256; j++)
			{
				if (state[j] == targetValue)
				{
					swapTarget = j;
					break;
				}
			}
		}
		else if (shieldIndexes.find(x) != shieldIndexes.end())
		{
			swapTarget = shieldIndexes[x];
		}
		else
		{
			swapTarget = 0; // We set zero aside so it could be used as a dumbing ground for useless side effects
		}

		if (swapTarget == -1) { throw std::runtime_error("Swap target not initialized!!!"); }

		int keyByte = (swapTarget - state[x] - y + 512) % 256;

		y = (y + state[x]+ keyByte) % 256;
		std::swap(state[x], state[y]);

		keyBuffer[x] = keyByte;
	}
}

void RC4HashCollider::ValidateParams()
{
	std::set<int> invariantValues;
	for (auto pair : invariants)
	{
		if (invariantValues.count(pair.second) > 0)
			throw std::runtime_error("Multiple invariants point to the same index! This is not possible.");

		invariantValues.insert(pair.second);
	}
}

bool RC4HashCollider::IsFreeIndex(int index)
{
	return index > 32 && index < lastByteBeforeIV && consumedIndexes.count(index) == 0;
}

bool RC4HashCollider::IsFreeValue(int value)
{
	return consumedValues.count(value) == 0;
}

void RC4HashCollider::ConsumeIndex(int index, C flags)
{
	if ((flags & C::BYPASS_INDEX_CHECK) == 0 && consumedIndexes.find(index) != consumedIndexes.end())
	{
		throw std::runtime_error("Index already taken!");
	}
	consumedIndexes.insert(index);
}

void RC4HashCollider::ConsumeValue(int value, C flags)
{
	if ((flags & C::BYPASS_VALUE_CHECK) == 0 && consumedValues.find(value) != consumedValues.end())
	{
		throw std::runtime_error("Value already taken!");
	}
	consumedValues.insert(value);
}

void RC4HashCollider::ConsumeSlot(int index, int value, C flags)
{
	ConsumeIndex(index, flags);
	ConsumeValue(value, flags);
	invariants[index] = value;
}

unsigned char* RC4HashCollider::GetKeyBytes()
{
	return keyBuffer;
}

int RC4HashCollider::GetKeyLength()
{
	return keyLength;
}