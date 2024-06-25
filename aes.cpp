#pragma once

#define AES_MODE_ECB 1
#define AES_MODE_CBC 2
#define AES_MODE_CFB 3
#define AES_MODE_OFB 4
#define AES_MODE_CTR 5

#define AES_KEY_LEN_128 128
#define AES_KEY_LEN_192 192
#define AES_KEY_LEN_256 256

#define AES_PADDING_MODE_NONE        0
#define AES_PADDING_MODE_PKCS7       1
#define AES_PADDING_MODE_ISO7816_4   2
#define AES_PADDING_MODE_ANSI923     3
#define AES_PADDING_MODE_ISO10126    4
#define AES_PADDING_MODE_ZERO        5

#define AES_ENC_ENCRYPT 1
#define AES_ENC_DECRYPT 0

int aesAlgorithm(
	const unsigned char* in,  int inLen, 
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int keyLen, int paddingMode,
	int enc
);

const unsigned char S_BOX[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const unsigned char ReS_BOX[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};

const unsigned char MixArray[4][4] = {
	0x02, 0x03, 0x01, 0x01,
	0x01, 0x02, 0x03, 0x01,
	0x01, 0x01, 0x02, 0x03,
	0x03, 0x01, 0x01, 0x02,
};

const unsigned char ReMixArray[4][4] = {
	0x0E, 0x0B, 0x0D, 0x09,
	0x09, 0x0E, 0x0B, 0x0D,
	0x0D, 0x09, 0x0E, 0x0B,
	0x0B, 0x0D, 0x09, 0x0E
};

const unsigned char Rcon[10] = {
	0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80,
	0x1B, 0x36,
};

int aesEncrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int paddingMode,
	int nk, int nr);
int aesDecrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int paddingMode,
	int nk, int nr);


void extendKey(const unsigned char* key, unsigned char subKey[4/*行.*/][60/*列.*/], int nk, int nr);
void AddRoundKey(unsigned char state[4/*行.*/][4/*列.*/], unsigned char subKey[4/*行.*/][60/*列.*/], int currentNr);
void SubBytes(unsigned char state[4/*行.*/][4/*列.*/]);
void ReSubBytes(unsigned char state[4/*行.*/][4/*列.*/]);
void ShiftRows(unsigned char state[4/*行.*/][4/*列.*/]);
void ReShiftRows(unsigned char state[4/*行.*/][4/*列.*/]);
void MixColumns(unsigned char state[4/*行.*/][4/*列.*/]);
void ReMixColumns(unsigned char state[4/*行.*/][4/*列.*/]);

int aesAlgorithm(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int keyLen, int paddingMode,
	int enc) {
	int nk, nr;

	switch (aesMode) {
	case AES_MODE_ECB:
		break;
	case AES_MODE_CBC:
		break;
	case AES_MODE_CFB:
		return 0;// 未支持
	case AES_MODE_OFB:
		return 0;// 未支持
	case AES_MODE_CTR:
		return 0;// 未支持
	default:
		return 0;
	}

	switch (keyLen) {
	case AES_KEY_LEN_128:
		nk = 4;
		nr = 10;
		break;
	case AES_KEY_LEN_192:
		nk = 6;
		nr = 12;
		break;
	case AES_KEY_LEN_256:
		nk = 8;
		nr = 14;
		break;
	default:
		return 0;
	}

	if ((paddingMode == AES_PADDING_MODE_NONE || enc == AES_ENC_DECRYPT) && inLen % 16 != 0) {
		return 0;
	}

	int resultLen = 0;
	if (enc == AES_ENC_ENCRYPT) {
		resultLen = aesEncrypt(in, inLen, key, iv, out, aesMode, paddingMode, nk, nr);
	}
	else if (enc == AES_ENC_DECRYPT) {
		resultLen = aesDecrypt(in, inLen, key, iv, out, aesMode, paddingMode, nk, nr);
	}
	else {
		return 0;
	}

	return resultLen;
}

int aesEncrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int paddingMode,
	int nk, int nr) {
	int resultLen = 0;
	// 分配内存
	unsigned char state    [4/*行.*/][ 4/*列.*/];
	unsigned char subKey   [4/*行.*/][60/*列.*/];

	// 密钥扩展
	extendKey(key, subKey, nk, nr);

	// 分组加密
	int modCount = inLen % 16;
	int encryptLen = inLen;
	if (paddingMode != AES_PADDING_MODE_NONE) {
		encryptLen = modCount != 0 ? inLen + modCount : inLen + 16;
	}
	for (int index = 0; index < encryptLen; index += 16) {
		for (int i = 0; i < 16; ++i) {
			if (index + i < inLen) {
				state[i & 0x03][i >> 2] = in[index + i];
			} else {
				if (paddingMode == AES_PADDING_MODE_PKCS7) {
					state[i & 0x03][i >> 2] = 16 - modCount;
				} else {
					return 0;
				}
			}
		}

		if (aesMode == AES_MODE_CBC) {
			if (index == 0) {
				for (int i = 0; i < 16; ++i) {
					state[i & 0x03][i >> 2] ^= iv[i];
				}
			} else {
				for (int i = 0; i < 16; ++i) {
					state[i & 0x03][i >> 2] ^= out[index - 16 + i];
				}
			}
		}

		// 在开始加密前先执行一次轮密钥加(密钥漂白)
		AddRoundKey(state, subKey, 0);

		// 开始加密
		for (int currentNr = 1; currentNr <= nr; ++currentNr) {
			// 字节代换层
			SubBytes(state);

			// 行位移
			ShiftRows(state);

			// 列混淆
			if (currentNr != nr) {// 最后一轮不进行列混淆
				MixColumns(state);
			}
			
			// 密钥加法层
			AddRoundKey(state, subKey, currentNr);
		}

		for (int i = 0; i < 16; ++i) {
			out[index + i] = state[i & 0x03][i >> 2];
		}
		resultLen += 16;
	}

	return resultLen;
}

int aesDecrypt(const unsigned char* in, int inLen,
	const unsigned char* key, const unsigned char* iv,
	unsigned char* out,
	int aesMode, int paddingMode,
	int nk, int nr) {
	int resultLen = 0;
	// 分配内存
	unsigned char state[4/*行.*/][4/*列.*/];
	unsigned char subKey[4/*行.*/][60/*列.*/];

	// 密钥扩展
	extendKey(key, subKey, nk, nr);

	// 分组加密
	for (int index = inLen - 16; index >= 0; index -= 16) {
		for (int i = 0; i < 16; ++i) {
			state[i & 0x03][i >> 2] = in[index + i];
		}

		// 开始解密
		for (int currentNr = nr; currentNr >= 1; --currentNr) {
			// 密钥加法层
			AddRoundKey(state, subKey, currentNr);

			// 列混淆
			if (currentNr != nr) {// 最后一轮不进行列混淆
				ReMixColumns(state);
			}

			// 行位移
			ReShiftRows(state);

			// 字节代换层
			ReSubBytes(state);
		}

		// 在解密后需要在执行一次轮密钥加(密钥漂白)
		AddRoundKey(state, subKey, 0);

		if (aesMode == AES_MODE_CBC) {
			if (index == 0) {
				for (int i = 0; i < 16; ++i) {
					state[i & 0x03][i >> 2] ^= iv[i];
				}
			} else {
				for (int i = 0; i < 16; ++i) {
					state[i & 0x03][i >> 2] ^= in[index - 16 + i];
				}
			}
		}

		for (int i = 0; i < 16; ++i) {
			if (paddingMode != AES_PADDING_MODE_NONE && index == inLen - 16) {
				if (paddingMode == AES_PADDING_MODE_PKCS7) {
					if ((16 - i) == state[i & 0x03][i >> 2]) {
						break;
					}
				} else {
					return 0;
				}
			}
			out[index + i] = state[i & 0x03][i >> 2];
			++resultLen;
		}
	}
	return resultLen;
}

void extendKey(const unsigned char* key, unsigned char subKey[4/*行.*/][60/*列.*/], int nk, int nr) {
	for (int i = 0; i < 4/*行.*/ * nk; ++i) {
		subKey[i & 0x03][i >> 2] = key[i];
	}

	unsigned char temp[4];
	int rconIndex = 0;
	for (int cloumn = nk; cloumn < (nr + 1) * 4; ++cloumn) {
		temp[0] = subKey[0][cloumn - 1];
		temp[1] = subKey[1][cloumn - 1];
		temp[2] = subKey[2][cloumn - 1];
		temp[3] = subKey[3][cloumn - 1];

		if (cloumn % nk == 0) {
			// 字循环
			unsigned int* tempIntptr = (unsigned int*)temp;
			*tempIntptr = (*tempIntptr) << 24 | (*tempIntptr) >> 8;
			// 字节代换
			temp[0] = S_BOX[temp[0]];
			temp[1] = S_BOX[temp[1]];
			temp[2] = S_BOX[temp[2]];
			temp[3] = S_BOX[temp[3]];
			// 轮常量异或
			temp[0] ^= Rcon[rconIndex++];
		} else if (nk == 8 && cloumn % 4 == 0) {
			// AES-256 的特殊处理
			// 字节代换
			temp[0] = S_BOX[temp[0]];
			temp[1] = S_BOX[temp[1]];
			temp[2] = S_BOX[temp[2]];
			temp[3] = S_BOX[temp[3]];
		}

		subKey[0][cloumn] = subKey[0][cloumn - nk] ^ temp[0];
		subKey[1][cloumn] = subKey[1][cloumn - nk] ^ temp[1];
		subKey[2][cloumn] = subKey[2][cloumn - nk] ^ temp[2];
		subKey[3][cloumn] = subKey[3][cloumn - nk] ^ temp[3];
	}
}

void AddRoundKey(unsigned char state[4/*行.*/][4/*列.*/], unsigned char subKey[4/*行.*/][60/*列.*/], int currentNr) {
	for (int row = 0; row < 4; ++row) {
		for (int cloumn = 0; cloumn < 4; ++cloumn) {
			state[row][cloumn] ^= subKey[row][currentNr * 4 + cloumn];
		}
	}
}

void SubBytes(unsigned char state[4/*行.*/][4/*列.*/]) {
	for (int row = 0; row < 4; ++row) {
		for (int cloumn = 0; cloumn < 4; ++cloumn) {
			state[row][cloumn] = S_BOX[state[row][cloumn]];
		}
	}
}

void ReSubBytes(unsigned char state[4/*行.*/][4/*列.*/]) {
	for (int row = 0; row < 4; ++row) {
		for (int cloumn = 0; cloumn < 4; ++cloumn) {
			state[row][cloumn] = ReS_BOX[state[row][cloumn]];
		}
	}
}

void ShiftRows(unsigned char state[4/*行.*/][4/*列.*/]) {
	unsigned int* tempIntPtr = (unsigned int*)state;
	tempIntPtr[1] = tempIntPtr[1] >>  8 | tempIntPtr[1] << 24;
	tempIntPtr[2] = tempIntPtr[2] >> 16 | tempIntPtr[2] << 16;
	tempIntPtr[3] = tempIntPtr[3] >> 24 | tempIntPtr[3] <<  8;
}

void ReShiftRows(unsigned char state[4/*行.*/][4/*列.*/]) {
	unsigned int* tempIntPtr = (unsigned int*)state;
	tempIntPtr[1] = tempIntPtr[1] <<  8 | tempIntPtr[1] >> 24;
	tempIntPtr[2] = tempIntPtr[2] << 16 | tempIntPtr[2] >> 16;
	tempIntPtr[3] = tempIntPtr[3] << 24 | tempIntPtr[3] >>  8;
}

unsigned char MixColumnsImpl(unsigned char mix, unsigned char num) {
	unsigned char result = 0;
	while (mix) {
		if (mix & 0x01) {
			result ^= num;
		}

		mix = mix >> 1;

		if (num & 0x80) {
			num = num << 1;
			num ^= 0x1B;
		} else {
			num = num << 1;
		}
	}
	return result;
}
void MixColumns(unsigned char state[4/*行.*/][4/*列.*/]) {
	unsigned char stateTemp[4/*行.*/][4/*列.*/];
	for (int row = 0; row < 4; ++row) {
		for (int cloumn = 0; cloumn < 4; ++cloumn) {
			stateTemp[row][cloumn] = state[row][cloumn];
		}
	}

	for (int row = 0; row < 4; ++row) {
		for (int cloumn = 0; cloumn < 4; ++cloumn) {
			state[row][cloumn] =
				MixColumnsImpl(MixArray[row][0], stateTemp[0][cloumn]) ^
				MixColumnsImpl(MixArray[row][1], stateTemp[1][cloumn]) ^
				MixColumnsImpl(MixArray[row][2], stateTemp[2][cloumn]) ^
				MixColumnsImpl(MixArray[row][3], stateTemp[3][cloumn]);
		}
	}
}
void ReMixColumns(unsigned char state[4/*行.*/][4/*列.*/]) {
	unsigned char stateTemp[4/*行.*/][4/*列.*/];
	for (int row = 0; row < 4; ++row) {
		for (int cloumn = 0; cloumn < 4; ++cloumn) {
			stateTemp[row][cloumn] = state[row][cloumn];
		}
	}

	for (int row = 0; row < 4; ++row) {
		for (int cloumn = 0; cloumn < 4; ++cloumn) {
			state[row][cloumn] =
				MixColumnsImpl(ReMixArray[row][0], stateTemp[0][cloumn]) ^
				MixColumnsImpl(ReMixArray[row][1], stateTemp[1][cloumn]) ^
				MixColumnsImpl(ReMixArray[row][2], stateTemp[2][cloumn]) ^
				MixColumnsImpl(ReMixArray[row][3], stateTemp[3][cloumn]);
		}
	}
}
