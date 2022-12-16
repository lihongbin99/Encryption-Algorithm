#include "sha.h"

#define convertIntEndian(num) (\
	((num >> 24) & 0x000000FF) | \
	((num >>  8) & 0x0000FF00) | \
	((num <<  8) & 0x00FF0000) | \
	((num << 24) & 0xFF000000) )

#define convertLongEndian(num) (\
	((num >> 56) & 0x00000000000000FF) | \
	((num >> 40) & 0x000000000000FF00) | \
	((num >> 24) & 0x0000000000FF0000) | \
	((num >>  8) & 0x00000000FF000000) | \
	((num <<  8) & 0x000000FF00000000) | \
	((num << 24) & 0x0000FF0000000000) | \
	((num << 40) & 0x00FF000000000000) | \
	((num << 56) & 0xFF00000000000000) )

void sha1Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out) {
	// 计算需要填充的数量
	int paddingCount = 64 - (messageLen % 64);
	paddingCount = paddingCount > 8 ? paddingCount : paddingCount + 64;
	paddingCount -= 8;// 最后8个字节用来保存数据长度

	unsigned long long dataLen = messageLen + paddingCount + 8;

	unsigned int A = 0x67452301;
	unsigned int B = 0xEFCDAB89;
	unsigned int C = 0x98BADCFE;
	unsigned int D = 0x10325476;
	unsigned int E = 0xC3D2E1F0;

	unsigned char buf[64];
	unsigned char w[80 * 32]; // 把 512bit 分为 16dword 再扩充为 80dword
	bool padding1 = true;
	for (int index = 0; index < dataLen; index += 64) {
		for (int i = 0; i < 64; ++i) {
			if (index + i < messageLen) {
				buf[i] = message[index + i];
			} else if (index + i == dataLen - 8) {
				*((unsigned long long*)(buf + i)) = convertLongEndian(messageLen << 3);
				break;
			} else if (padding1) {
				buf[i] = 0x80;
				padding1 = false;
			} else {
				buf[i] = 0;
			}
		}

		// 数据扩充
		unsigned int* intPtr = (unsigned int*)w;
		for (int wi = 0; wi < 80; wi++) {
			if (wi < 16) {
				*(intPtr + wi) = ((unsigned int*)buf)[wi];
			} else {
				unsigned int num = convertIntEndian(intPtr[wi - 3]) ^ \
					convertIntEndian(intPtr[wi -  8]) ^ \
					convertIntEndian(intPtr[wi - 14]) ^ \
					convertIntEndian(intPtr[wi - 16]);
				*(intPtr + wi) = convertIntEndian((num << 1 | num >> 31));
			}
		}

		unsigned int a = A;
		unsigned int b = B;
		unsigned int c = C;
		unsigned int d = D;
		unsigned int e = E;

		// 主循环
		for (int i = 0; i < 80; ++i) {
			unsigned int f, k;
			if (i < 20) {
				f = d ^ (b & (c ^ d));
				k = 0x5A827999;
			}
			else if (i < 40) {
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if (i < 60) {
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}
			else {
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			unsigned tj = a;
			tj = tj << 5 | tj >> 27;
			tj += f;
			tj += e;
			tj += k;
			tj += convertIntEndian(intPtr[i]);
			e = tj;

			b = b << 30 | b >> 2;

			unsigned int te = e;
			e = d;
			d = c;
			c = b;
			b = a;
			a = te;
		}

		// 最终处理
		A += a;
		B += b;
		C += c;
		D += d;
		E += e;
	}

	*((unsigned int*)out + 0) = convertIntEndian(A);
	*((unsigned int*)out + 1) = convertIntEndian(B);
	*((unsigned int*)out + 2) = convertIntEndian(C);
	*((unsigned int*)out + 3) = convertIntEndian(D);
	*((unsigned int*)out + 4) = convertIntEndian(E);
}

void doSha256Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out, int bit) {
	unsigned int h0;
	unsigned int h1;
	unsigned int h2;
	unsigned int h3;
	unsigned int h4;
	unsigned int h5;
	unsigned int h6;
	unsigned int h7;

	if (bit == 224) {
		h0 = 0xc1059ed8;
		h1 = 0x367cd507;
		h2 = 0x3070dd17;
		h3 = 0xf70e5939;
		h4 = 0xffc00b31;
		h5 = 0x68581511;
		h6 = 0x64f98fa7;
		h7 = 0xbefa4fa4;
	}
	else if (bit == 256) {
		h0 = 0x6a09e667;
		h1 = 0xbb67ae85;
		h2 = 0x3c6ef372;
		h3 = 0xa54ff53a;
		h4 = 0x510e527f;
		h5 = 0x9b05688c;
		h6 = 0x1f83d9ab;
		h7 = 0x5be0cd19;
	}
	else {
		return;
	}

	unsigned int k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

	// 计算需要填充的数量
	int paddingCount = 64 - (messageLen % 64);
	paddingCount = paddingCount > 8 ? paddingCount : paddingCount + 64;
	paddingCount -= 8;// 最后8个字节用来保存数据长度

	unsigned long long dataLen = messageLen + paddingCount + 8;

	unsigned char buf[64];
	unsigned char w[64 * 32]; // 把 512bit 分为 16dword 再扩充为 64dword
	bool padding1 = true;
	for (int index = 0; index < dataLen; index += 64) {
		for (int i = 0; i < 64; ++i) {
			if (index + i < messageLen) {
				buf[i] = message[index + i];
			} else if (index + i == dataLen - 8) {
				*((unsigned long long*)(buf + i)) = convertLongEndian(messageLen << 3);
				break;
			} else if (padding1) {
				buf[i] = 0x80;
				padding1 = false;
			} else {
				buf[i] = 0;
			}
		}

		unsigned int* intPtr = (unsigned int*)w;
		for (int wi = 0; wi < 64; wi++) {
			if (wi < 16) {
				*(intPtr + wi) = ((unsigned int*)buf)[wi];
			} else {
				unsigned int s0 = convertIntEndian(intPtr[wi - 15]);
				unsigned int s1 = convertIntEndian(intPtr[wi -  2]);
				unsigned int s2 = convertIntEndian(intPtr[wi - 16]);
				unsigned int s3 = convertIntEndian(intPtr[wi -  7]);
				s0 = ((s0 >>  7) | (s0 << 25)) ^ ((s0 >> 18) | (s0 << 14)) ^ (s0 >>  3);
				s1 = ((s1 >> 17) | (s1 << 15)) ^ ((s1 >> 19) | (s1 << 13)) ^ (s1 >> 10);
				*(intPtr + wi) = convertIntEndian((s0 + s1 + s2 + s3));
			}
		}

		unsigned int a = h0;
		unsigned int b = h1;
		unsigned int c = h2;
		unsigned int d = h3;
		unsigned int e = h4;
		unsigned int f = h5;
		unsigned int g = h6;
		unsigned int h = h7;

		// 主循环
		unsigned int temp1, temp2;
		for (int i = 0; i < 64; ++i) {
			unsigned int S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
			unsigned int ch = (e & f) ^ ((~e) & g);
			temp1 = h + S1 + ch + k[i] + convertIntEndian(intPtr[i]);
			unsigned int S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
			unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		// 最终处理
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	*((unsigned int*)out + 0) = convertIntEndian(h0);
	*((unsigned int*)out + 1) = convertIntEndian(h1);
	*((unsigned int*)out + 2) = convertIntEndian(h2);
	*((unsigned int*)out + 3) = convertIntEndian(h3);
	*((unsigned int*)out + 4) = convertIntEndian(h4);
	*((unsigned int*)out + 5) = convertIntEndian(h5);
	*((unsigned int*)out + 6) = convertIntEndian(h6);
	if (bit == 256) {
		*((unsigned int*)out + 7) = convertIntEndian(h7);
	}
}
void sha224Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out) {
	doSha256Encode(message, messageLen, out, 224);
}

void sha256Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out) {
	doSha256Encode(message, messageLen, out, 256);
}

void doSha512Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out, int bit) {
	unsigned long long h0;
	unsigned long long h1;
	unsigned long long h2;
	unsigned long long h3;
	unsigned long long h4;
	unsigned long long h5;
	unsigned long long h6;
	unsigned long long h7;

	if (bit == 384) {
		h0 = 0xcbbb9d5dc1059ed8;
		h1 = 0x629a292a367cd507;
		h2 = 0x9159015a3070dd17;
		h3 = 0x152fecd8f70e5939;
		h4 = 0x67332667ffc00b31;
		h5 = 0x8eb44a8768581511;
		h6 = 0xdb0c2e0d64f98fa7;
		h7 = 0x47b5481dbefa4fa4;
	}
	else if (bit == 512) {
		h0 = 0x6a09e667f3bcc908;
		h1 = 0xbb67ae8584caa73b;
		h2 = 0x3c6ef372fe94f82b;
		h3 = 0xa54ff53a5f1d36f1;
		h4 = 0x510e527fade682d1;
		h5 = 0x9b05688c2b3e6c1f;
		h6 = 0x1f83d9abfb41bd6b;
		h7 = 0x5be0cd19137e2179;
	}
	else {
		return;
	}

	unsigned long long k[80] = {
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
			0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
			0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
			0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
			0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
			0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
			0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
			0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
			0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
			0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
			0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
			0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
			0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	};

	// 计算需要填充的数量
	int paddingCount = 128 - (messageLen % 128);
	paddingCount = paddingCount > 16 ? paddingCount : paddingCount + 128;
	paddingCount -= 16;// 最后16个字节用来保存数据长度

	unsigned long long dataLen = messageLen + paddingCount + 16;

	unsigned char buf[128];
	unsigned char w[80 * 64]; // 把 1024bit 分为 16qword 再扩充为 80qword
	bool padding1 = true;
	for (int index = 0; index < dataLen; index += 128) {
		for (int i = 0; i < 128; ++i) {
			if (index + i < messageLen) {
				buf[i] = message[index + i];
			} else if (index + i == dataLen - 16) {
				*((unsigned long long*)(buf + i + 0)) = convertLongEndian(((messageLen >> 61) & 0x7));
				*((unsigned long long*)(buf + i + 8)) = convertLongEndian(  messageLen <<  3);
				break;
			} else if (padding1) {
				buf[i] = 0x80;
				padding1 = false;
			} else {
				buf[i] = 0;
			}
		}

		// 数据填充
		unsigned long long* longPtr = (unsigned long long*)w;
		for (int wi = 0; wi < 80; wi++) {
			if (wi < 16) {
				*(longPtr + wi) = ((unsigned long long*)buf)[wi];
			} else {
				unsigned long long s0 = convertLongEndian(longPtr[wi - 15]);
				unsigned long long s1 = convertLongEndian(longPtr[wi -  2]);
				unsigned long long s2 = convertLongEndian(longPtr[wi - 16]);
				unsigned long long s3 = convertLongEndian(longPtr[wi -  7]);
				s0 = ((s0 >>  1) | (s0 << 63)) ^ ((s0 >>  8) | (s0 << 56)) ^ (s0 >> 7);
				s1 = ((s1 >> 19) | (s1 << 45)) ^ ((s1 >> 61) | (s1 <<  3)) ^ (s1 >> 6);
				*(longPtr + wi) = convertLongEndian((s0 + s1 + s2 + s3));
			}
		}

		unsigned long long a = h0;
		unsigned long long b = h1;
		unsigned long long c = h2;
		unsigned long long d = h3;
		unsigned long long e = h4;
		unsigned long long f = h5;
		unsigned long long g = h6;
		unsigned long long h = h7;

		// 主循环
		unsigned long long temp1, temp2;
		for (int i = 0; i < 80; ++i) {
			unsigned long long S1 = ((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23));
			unsigned long long ch = (e & f) ^ ((~e) & g);
			temp1 = h + S1 + ch + k[i] + convertLongEndian(longPtr[i]);

			unsigned long long S0 = ((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25));
			unsigned long long maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		// 最终处理
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	*((unsigned long long*)out + 0) = convertLongEndian(h0);
	*((unsigned long long*)out + 1) = convertLongEndian(h1);
	*((unsigned long long*)out + 2) = convertLongEndian(h2);
	*((unsigned long long*)out + 3) = convertLongEndian(h3);
	*((unsigned long long*)out + 4) = convertLongEndian(h4);
	*((unsigned long long*)out + 5) = convertLongEndian(h5);
	if (bit == 512) {
		*((unsigned long long*)out + 6) = convertLongEndian(h6);
		*((unsigned long long*)out + 7) = convertLongEndian(h7);
	}
}
void sha384Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out) {
	doSha512Encode(message, messageLen, out, 384);
}
void sha512Encode(const unsigned char* message, unsigned long long messageLen, unsigned char* out) {
	doSha512Encode(message, messageLen, out, 512);
}
