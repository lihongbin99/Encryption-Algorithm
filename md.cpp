#pragma once

#define MD5_GROUP_BIT 512
#define MD5_GROUP_LEN (MD5_GROUP_BIT / 8)
#define MD5_LAST_BIT  64
#define MD5_LAST_LEN  (MD5_LAST_BIT / 8)

void md5Encode(const unsigned char* message, int messageLen, unsigned char* out);

unsigned char s[]{
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

unsigned int K[]{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

void md5Encode(const unsigned char* message, int messageLen, unsigned char* out) {
	// 计算需要填充的数量
	int paddingCount = 64 - (messageLen % 64);
	paddingCount = paddingCount > 8 ? paddingCount : paddingCount + 64;
	paddingCount -= 8;// 最后8个字节用来保存数据长度

	unsigned long long dataLen = messageLen + paddingCount + 8;

	unsigned int A = 0x67452301;
	unsigned int B = 0xEFCDAB89;
	unsigned int C = 0x98BADCFE;
	unsigned int D = 0x10325476;

	unsigned char buf[64];
	bool padding1 = true;
	for (int index = 0; index < dataLen; index += 64) {
		for (int i = 0; i < 64; ++i) {
			if (index + i < messageLen) {
				buf[i] = message[index + i];
			}
			else if (index + i == dataLen - 8) {
				unsigned long long lastLen = messageLen * 8;
				*((unsigned long long*)(buf + i)) = lastLen;
				break;
			}
			else if (padding1) {
				buf[i] = 0x80;
				padding1 = false;
			}
			else {
				buf[i] = 0;
			}
		}

		unsigned int a = A;
		unsigned int b = B;
		unsigned int c = C;
		unsigned int d = D;

		// 主循环
		for (int i = 0; i < 64; ++i) {
			unsigned int F, g;

			if (i < 16) {
				F = (b & c) | ((~b) & d);
				g = i;
			}
			else if (i < 32) {
				F = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48) {
				F = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			}
			else {
				F = c ^ (b | (~d));
				g = (7 * i) % 16;
			}

			F += a + K[i]  + ((unsigned int*)buf)[g];
			
			a = d;
			d = c;
			c = b;
			b += (F << s[i]) | (F >> (32 - s[i]));
		}

		// 最终处理
		A += a;
		B += b;
		C += c;
		D += d;
	}

	*((unsigned int*)out + 0) = A;
	*((unsigned int*)out + 1) = B;
	*((unsigned int*)out + 2) = C;
	*((unsigned int*)out + 3) = D;
}
