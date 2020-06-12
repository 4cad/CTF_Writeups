
#include <iostream>
#include <vector>
#include <algorithm>
#include <inttypes.h>

using namespace std;

uint16_t shift(uint16_t n, uint8_t i) {
    uint16_t n1 = (n << i) % 0x800;
    uint16_t n2 = (n >> (11 - i));
    return n1 ^ n2;
}

uint16_t PIE(uint8_t i, uint16_t A, uint16_t B, uint16_t C) {
    if(i < 16) {
        return (A & B) | ((~A) & C);
    } else {
        return (A & B) | (B & C) | (C & A);
    }
}

uint8_t pie(uint8_t j) {
    if (j < 16)
        return j;
    switch (j) {
    case 16: return 0;
    case 17: return 4;
    case 18: return 8;
    case 19: return 12;
    case 20: return 1;
    case 21: return 5;
    case 22: return 9;
    case 23: return 13;
    case 24: return 2;
    case 25: return 6;
    case 26: return 10;
    case 27: return 14;
    case 28: return 3;
    case 29: return 7;;
    case 30: return 11;
    default:
        return 15;
    }
}

size_t Hash(uint16_t X[20]) {
    uint8_t n = 3;
    uint8_t s[32] = {
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
    };
    uint16_t Q[36] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    uint16_t m[16] = {0, 0, 0, 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 };
        
    for (int i = -3; i < 1; i++) {
        Q[n + i] = X[i + 3];
    }

    for (uint8_t i = 0; i < 16; i++) {
        m[i] = X[i + 4];
    }

    for (uint8_t i = 0; i < 32; i++) {
        Q[n + i + 1] = shift(((Q[n + i - 3] + PIE(i, Q[n + i], Q[n + i - 1], Q[n + i - 2]) + m[pie(i)]) % 0x800), s[i]);
    }
 
    size_t Y[4];
    for (uint8_t i = 0; i < 4; i++) {
        Y[i] = ((Q[n + i - 3] + Q[32 + i]) % 0x800);
    }

    Y[1] = (Y[0] << 33) ^ (Y[1] << 22);
    Y[0] = Y[2] << 11;
    Y[1] ^= Y[0] ^ Y[3];
    return Y[1];
}

using namespace std;

void ParameterizedAttack(size_t target, int baseIdx, int overrideIdx, int overrideIdx2 = -1) {
    size_t origTarget = target;
    std::vector<std::pair<uint16_t, uint16_t>> offsets = {
        {0,0},{1,640},{2,1280},{4,513},{8,1026},{16,5},{32,10},{64,20},{128,40},{256,80},{512,160},{1024,320}
    };

    uint16_t values[20] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint16_t mockQ[36] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    uint16_t Y[4];
    for (uint8_t i = 0; i < 4; i++) {
        Y[3-i] = target & 0x7ff;
        target >>= 11;
    }

    for (uint16_t a = 0; a < 0x800; a++) {
        Y[overrideIdx] = a;
        for (uint16_t b = 0; b < 0x800; b++) {
            if (overrideIdx2 == -1) {
                b = 0x800; // Only loop once
            }
            else {
                Y[overrideIdx2] = b;
            }

            auto offsetsBegin = offsets.begin();
            auto offsetsEnd = offsets.end();
            if (baseIdx >= 9) {
                offsetsEnd = offsetsBegin + 1; // Only do the (0,0) offset
            }

            for (auto offset = offsetsBegin; offset != offsetsEnd; offset++) {
                uint16_t jitterValue = offset->first;
                uint16_t jitterOffset = offset->second;

                for (int i = 0; i < 4; i++) {
                    values[i] = Y[i];
                }

                if (baseIdx < 9) {
                    values[3] = (values[3] + 0x800 - jitterOffset) % 0x800;
                    values[19] = jitterValue;
                }

                for (int i = 0; i < 4; i++) {
                    mockQ[i] = values[i];
                }

                std::fill_n(mockQ + 4, 20, 0); // could do 32 but we wont use it
                uint16_t nullifier[16];
                for (int i = 0; i < 16; i++) {
                    uint16_t left = (mockQ[i] + PIE(i, mockQ[3 + i], mockQ[i + 2], mockQ[i + 1])) % 0x800;
                    uint16_t right = 0x800 - left;
                    if (i < baseIdx) {
                        right = 0;
                    }
                    nullifier[i] = right;
                    mockQ[3 + i + 1] = shift(((right + mockQ[3 + i - 3] + PIE(i, mockQ[3 + i], mockQ[3 + i - 1], mockQ[3 + i - 2])) % 0x800), 3);
                }

                for (int i = 0; i < 4; i++) {
                    values[4 + baseIdx + i] = nullifier[baseIdx + i];
                }

                size_t result = Hash(values); 
                if (result == origTarget) {
                    printf("[");
                    for (int i = 0; i < 20; i++) {
                        printf("%d", values[i]);
                        if (i != 19) {
                            printf(", ");
                        }
                    }
                    printf("],");
                }
            }
        }
    }
}

void Attack(size_t target) {
    ParameterizedAttack(target, 0, 0);
    ParameterizedAttack(target, 4, 1);
    ParameterizedAttack(target, 8, 2);
    ParameterizedAttack(target, 12, 3);

    ParameterizedAttack(target, 11, 2, 3);
}

#include <sstream>

int main(int argc, char* argv[], char* envp[]) {
    const char* arg = argv[1];
    char* pEnd; 
    
    size_t target;
    std::istringstream iss(arg);
    iss >> target;

    printf("[");
    Attack(target);
    printf("]");
	return 0;
}