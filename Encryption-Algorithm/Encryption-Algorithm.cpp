#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#define USE_OPENSSL

#ifdef USE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#endif

#include "encrypt/md.h"
#include "encrypt/sha.h"
#include "encrypt/hmac.h"
#include "encrypt/kdf.h"
#include "encrypt/aes.h"

void md5Test() {
	const unsigned char message[13520] = "Hello World!";
	const int messageLen = sizeof(message) - 1;

#ifdef USE_OPENSSL
	unsigned char opensslMD5Out[16];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, message, messageLen);
	MD5_Final(opensslMD5Out, &ctx);
	printf(" md5Encode: ");
	for (int i = 0; i < sizeof(opensslMD5Out); ++i) {
		printf("%02X ", (int)opensslMD5Out[i]);
	}
	printf("\n");
#endif

	unsigned char md5[16];
	md5Encode(message, messageLen, md5);
	printf("       md5: ");
	for (int i = 0; i < sizeof(md5); ++i) {
		printf("%02X ", (int)md5[i]);
	}
	printf("\n");
}

void sha1Test() {
	const unsigned char message[] = "Hello World!";
	const int messageLen = sizeof(message) - 1;
	
#ifdef USE_OPENSSL
	unsigned char opensslSha1Out[SHA1_OUTLEN];
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, message, messageLen);
	SHA1_Final(opensslSha1Out, &ctx);
	printf("opensslSha1: ");
	for (int i = 0; i < sizeof(opensslSha1Out); ++i) {
		printf("%02X ", (int)opensslSha1Out[i]);
	}
	printf("\n");
#endif

	unsigned char sha1[SHA1_OUTLEN];
	sha1Encode(message, messageLen, sha1);
	printf("       sha1: ");
	for (int i = 0; i < sizeof(sha1); ++i) {
		printf("%02X ", (int)sha1[i]);
	}
	printf("\n");
}

void sha2Test() {
	const unsigned char message[] = "Hello World!";
	const int messageLen = sizeof(message) - 1;

#ifdef USE_OPENSSL
	unsigned char opensslSha224Out[SHA224_OUTLEN];
	SHA256_CTX ctx224;
	SHA224_Init(&ctx224);
	SHA224_Update(&ctx224, message, messageLen);
	SHA224_Final(opensslSha224Out, &ctx224);
	printf("opensslSha224: ");
	for (int i = 0; i < sizeof(opensslSha224Out); ++i) {
		printf("%02X ", (int)opensslSha224Out[i]);
	}
	printf("\n");
#endif

	unsigned char sha224[SHA224_OUTLEN];
	sha224Encode(message, messageLen, sha224);
	printf("       sha224: ");
	for (int i = 0; i < sizeof(sha224); ++i) {
		printf("%02X ", (int)sha224[i]);
	}
	printf("\n");

	/**************************************************************************************/

#ifdef USE_OPENSSL
	unsigned char opensslSha256Out[SHA256_OUTLEN];
	SHA256_CTX ctx256;
	SHA256_Init(&ctx256);
	SHA256_Update(&ctx256, message, messageLen);
	SHA256_Final(opensslSha256Out, &ctx256);
	printf("opensslSha256: ");
	for (int i = 0; i < sizeof(opensslSha256Out); ++i) {
		printf("%02X ", (int)opensslSha256Out[i]);
	}
	printf("\n");
#endif

	unsigned char sha256[SHA256_OUTLEN];
	sha256Encode(message, messageLen, sha256);
	printf("       sha256: ");
	for (int i = 0; i < sizeof(sha256); ++i) {
		printf("%02X ", (int)sha256[i]);
	}
	printf("\n");

	/**************************************************************************************/

#ifdef USE_OPENSSL
	unsigned char opensslSha384Out[SHA384_OUTLEN];
	SHA512_CTX ctx384;
	SHA384_Init(&ctx384);
	SHA384_Update(&ctx384, message, messageLen);
	SHA384_Final(opensslSha384Out, &ctx384);
	printf("opensslSha384: ");
	for (int i = 0; i < sizeof(opensslSha384Out); ++i) {
		printf("%02X ", (int)opensslSha384Out[i]);
	}
	printf("\n");
#endif

	unsigned char sha384[SHA384_OUTLEN];
	sha384Encode(message, messageLen, sha384);
	printf("       sha384: ");
	for (int i = 0; i < sizeof(sha384); ++i) {
		printf("%02X ", (int)sha384[i]);
	}
	printf("\n");

	/**************************************************************************************/

#ifdef USE_OPENSSL
	unsigned char opensslSha512Out[SHA512_OUTLEN];
	SHA512_CTX ctx512;
	SHA512_Init(&ctx512);
	SHA512_Update(&ctx512, message, messageLen);
	SHA512_Final(opensslSha512Out, &ctx512);
	printf("opensslSha512: ");
	for (int i = 0; i < sizeof(opensslSha512Out); ++i) {
		printf("%02X ", (int)opensslSha512Out[i]);
	}
	printf("\n");
#endif

	unsigned char sha512[SHA512_OUTLEN];
	sha512Encode(message, messageLen, sha512);
	printf("       sha512: ");
	for (int i = 0; i < sizeof(sha512); ++i) {
		printf("%02X ", (int)sha512[i]);
	}
	printf("\n");
}

void hmacTest() {
	const unsigned char message[] = "Hello World!";
	const int messageLen = sizeof(message) - 1;
	const unsigned char macKey[256]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x88 };

#ifdef USE_OPENSSL
	unsigned char opensslHmacOut[20];
	HMAC_CTX* hctx = HMAC_CTX_new();
	HMAC_Init_ex(hctx, macKey, sizeof(macKey), EVP_sha1(), NULL);
	HMAC_Update(hctx, message, messageLen);
	HMAC_Final(hctx, opensslHmacOut, NULL);
	HMAC_CTX_free(hctx);
	cout << "opensslHmac: ";
	for (int i = 0; i < sizeof(opensslHmacOut); ++i) {
		printf("%02X ", (int)opensslHmacOut[i]);
	}
	cout << endl;
#endif

	unsigned char hmacOut[20];
	hmacSha1(macKey, sizeof(macKey), message, messageLen, hmacOut);
	cout << "   hmacSha1: ";
	for (int i = 0; i < sizeof(hmacOut); ++i) {
		printf("%02X ", (int)hmacOut[i]);
	}
	cout << endl;
}

void kdfTest() {
	const unsigned char message[] = "Hello World!";
	const int messageLen = sizeof(message) - 1;
	const unsigned char kdfKey[0x20]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
	const unsigned char kdfIv[0x20]{ 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21 };
	
#ifdef USE_OPENSSL
	unsigned char opensslKdfOut[0x20];
	PKCS5_PBKDF2_HMAC_SHA1((const char*)kdfKey, sizeof(kdfKey), kdfIv, sizeof(kdfIv), 64000, sizeof(opensslKdfOut), opensslKdfOut);
	cout << " opensslKdf: ";
	for (int i = 0; i < sizeof(opensslKdfOut); ++i) {
		printf("%02X ", (int)opensslKdfOut[i]);
	}
	cout << endl;
#endif

	unsigned char kdfOut[0x20];
	kdfHmacSha1(kdfKey, sizeof(kdfKey), kdfIv, sizeof(kdfIv), 64000, sizeof(kdfOut), kdfOut);
	cout << "kdfHmacSha1: ";
	for (int i = 0; i < sizeof(kdfOut); ++i) {
		printf("%02X ", (int)kdfOut[i]);
	}
	cout << endl;
}

void aesTest() {
	const unsigned char aesMsg[32]{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
	const unsigned char aesKey[32]{ 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21 };
	// const unsigned char aesMsg[16]{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34, };
	// const unsigned char aesKey[16]{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, };
	const unsigned char aesIv [32]{ 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22 };
	unsigned char opensslAesOut[1024];
	unsigned char aesOut[1024];
	int totalLen;
	
#ifdef USE_OPENSSL
	EVP_CIPHER_CTX* ectx;
	int opensslTotalLen = 0;
	int decryptLen = 0;
#endif

#ifdef USE_OPENSSL
	ectx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ectx, EVP_aes_128_ecb(), NULL, aesKey, NULL, AES_DECRYPT);
	EVP_CIPHER_CTX_set_padding(ectx, 0);
	opensslTotalLen = 0;
	decryptLen = 0;
	EVP_CipherUpdate(ectx, opensslAesOut, &decryptLen, aesMsg, sizeof(aesMsg));
	opensslTotalLen += decryptLen;
	decryptLen = 0;
	EVP_CipherFinal_ex(ectx, opensslAesOut + opensslTotalLen, &decryptLen);
	opensslTotalLen += decryptLen;
	EVP_CIPHER_CTX_free(ectx);
	cout << "opensslAes128ecb: ";
	for (int i = 0; i < opensslTotalLen; ++i) {
		printf("%02X ", (int)opensslAesOut[i]);
	}
	cout << endl;
#endif

	memset(aesOut, 0x8, sizeof(aesOut));
	totalLen = aesAlgorithm(
		aesMsg, sizeof(aesMsg),
		aesKey, NULL,
		aesOut,
		AES_MODE_ECB, AES_KEY_LEN_128, AES_PADDING_MODE_NONE,
		AES_ENC_DECRYPT
	);
	cout << "       aes128ecb: ";
	for (int i = 0; i < totalLen; ++i) {
		printf("%02X ", (int)aesOut[i]);
	}
	cout << endl;

	/*****************************************************************/

#ifdef USE_OPENSSL
	ectx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ectx, EVP_aes_128_cbc(), NULL, aesKey, aesIv, AES_DECRYPT);
	EVP_CIPHER_CTX_set_padding(ectx, 0);
	opensslTotalLen = 0;
	decryptLen = 0;
	EVP_CipherUpdate(ectx, opensslAesOut, &decryptLen, aesMsg, sizeof(aesMsg));
	opensslTotalLen += decryptLen;
	decryptLen = 0;
	EVP_CipherFinal_ex(ectx, opensslAesOut + opensslTotalLen, &decryptLen);
	opensslTotalLen += decryptLen;
	EVP_CIPHER_CTX_free(ectx);
	cout << "opensslAes128cbc: ";
	for (int i = 0; i < opensslTotalLen; ++i) {
		printf("%02X ", (int)opensslAesOut[i]);
	}
	cout << endl;
#endif

	totalLen = aesAlgorithm(
		aesMsg, sizeof(aesMsg),
		aesKey, aesIv,
		aesOut,
		AES_MODE_CBC, AES_KEY_LEN_128, AES_PADDING_MODE_NONE,
		AES_ENC_DECRYPT
	);
	cout << "       aes128cbc: ";
	for (int i = 0; i < totalLen; ++i) {
		printf("%02X ", (int)aesOut[i]);
	}
	cout << endl;

	/*****************************************************************/

#ifdef USE_OPENSSL
	ectx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ectx, EVP_aes_256_cbc(), NULL, aesKey, aesIv, AES_DECRYPT);
	EVP_CIPHER_CTX_set_padding(ectx, 0);
	opensslTotalLen = 0;
	decryptLen = 0;
	EVP_CipherUpdate(ectx, opensslAesOut, &decryptLen, aesMsg, sizeof(aesMsg));
	opensslTotalLen += decryptLen;
	decryptLen = 0;
	EVP_CipherFinal_ex(ectx, opensslAesOut + opensslTotalLen, &decryptLen);
	opensslTotalLen += decryptLen;
	EVP_CIPHER_CTX_free(ectx);
	cout << "opensslAes256cbc: ";
	for (int i = 0; i < opensslTotalLen; ++i) {
		printf("%02X ", (int)opensslAesOut[i]);
	}
	cout << endl;
#endif

	totalLen = aesAlgorithm(
		aesMsg, sizeof(aesMsg),
		aesKey, aesIv,
		aesOut,
		AES_MODE_CBC, AES_KEY_LEN_256, AES_PADDING_MODE_NONE,
		AES_ENC_DECRYPT
	);
	cout << "       aes256cbc: ";
	for (int i = 0; i < totalLen; ++i) {
		printf("%02X ", (int)aesOut[i]);
	}
	cout << endl;

#ifdef USE_OPENSSL
	ectx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ectx, EVP_aes_256_cbc(), NULL, aesKey, aesIv, AES_ENCRYPT);
	EVP_CIPHER_CTX_set_padding(ectx, EVP_PADDING_PKCS7);
	opensslTotalLen = 0;
	decryptLen = 0;
	EVP_CipherUpdate(ectx, opensslAesOut, &decryptLen, aesMsg, sizeof(aesMsg));
	opensslTotalLen += decryptLen;
	decryptLen = 0;
	EVP_CipherFinal_ex(ectx, opensslAesOut + opensslTotalLen, &decryptLen);
	opensslTotalLen += decryptLen;
	EVP_CIPHER_CTX_free(ectx);
	cout << "opensslAes256cbc_pkcs7: ";
	for (int i = 0; i < opensslTotalLen; ++i) {
		printf("%02X ", (int)opensslAesOut[i]);
	}
	cout << endl;
#endif

	totalLen = aesAlgorithm(
		aesMsg, sizeof(aesMsg),
		aesKey, aesIv,
		aesOut,
		AES_MODE_CBC, AES_KEY_LEN_256, AES_PADDING_MODE_PKCS7,
		AES_ENC_ENCRYPT
	);
	cout << "       aes256cbc_pkcs7: ";
	for (int i = 0; i < totalLen; ++i) {
		printf("%02X ", (int)aesOut[i]);
	}
	cout << endl;
}

int main() {
	md5Test();
	cout << endl;
	sha1Test();
	cout << endl;
	sha2Test();
	cout << endl;
	hmacTest();
	cout << endl;
	kdfTest();
	cout << endl;
	aesTest();
	cout << endl;

	return EXIT_SUCCESS;
}
