#pragma once

#include<cstring>

#include "sha.cpp"

void hmacSha1(const unsigned char* key, int keyLen, const unsigned char* message, int messageLen, unsigned char* out);

#define SHA1_GROUP_LEN 64

void hmacSha1(const unsigned char* key, int keyLen, const unsigned char* message, int messageLen, unsigned char* out) {
	// Ěîłä Key
	unsigned char hmacKey[64];
	if (keyLen > SHA1_GROUP_LEN) {
		sha1Encode(key, keyLen, hmacKey);
		keyLen = 20;
	} else {
		memcpy(hmacKey, key, keyLen);
	}
	if (keyLen < SHA1_GROUP_LEN) {
		for (int i = keyLen; i < SHA1_GROUP_LEN; ++i) {
			hmacKey[i] = 0;
		}
		keyLen = SHA1_GROUP_LEN;
	}

	unsigned char keyPad[SHA1_GROUP_LEN * 2];
	for (int i = 0; i < SHA1_GROUP_LEN; ++i) {
		keyPad[i] = hmacKey[i] ^ 0x5C;// oPad
		keyPad[SHA1_GROUP_LEN + i] = hmacKey[i] ^ 0x36;// iPad
	}

	unsigned char* newMessage = new unsigned char[SHA1_GROUP_LEN + messageLen];
	memcpy(newMessage, keyPad + SHA1_GROUP_LEN, SHA1_GROUP_LEN);
	memcpy(newMessage + SHA1_GROUP_LEN, message, messageLen);
	sha1Encode(newMessage, SHA1_GROUP_LEN + messageLen, keyPad + SHA1_GROUP_LEN);
	delete[] newMessage;

	sha1Encode(keyPad, SHA1_GROUP_LEN + 20, keyPad + SHA1_GROUP_LEN + 20);

	memcpy(out, keyPad + SHA1_GROUP_LEN + 20, 20);
}
