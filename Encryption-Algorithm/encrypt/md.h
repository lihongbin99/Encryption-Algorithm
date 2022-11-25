#pragma once

#include "base.h"

#define MD5_GROUP_BIT 512
#define MD5_GROUP_LEN (MD5_GROUP_BIT / 8)
#define MD5_LAST_BIT  64
#define MD5_LAST_LEN  (MD5_LAST_BIT / 8)

void md5Encode(const unsigned char* message, int messageLen, unsigned char* out);
