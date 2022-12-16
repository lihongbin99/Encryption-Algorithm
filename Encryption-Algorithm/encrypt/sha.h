#pragma once

#include "base.h"

#define SHA1_OUTLEN 20
void sha1Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out);

#define SHA224_OUTLEN 28
void sha224Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out);

#define SHA256_OUTLEN 32
void sha256Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out);

#define SHA384_OUTLEN 48
void sha384Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out);

#define SHA512_OUTLEN 64
void sha512Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out);
