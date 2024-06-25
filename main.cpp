#include "md.cpp"
#include "sha.cpp"
#include "hmac.cpp"
#include "kdf.cpp"
#include "aes.cpp"
#include "rsa.cpp"

#include <iostream>
using namespace std;

int main() {
    const unsigned char message[] = "Hello World!";
    const unsigned char key[]     = "0123456789ABCDEF";
    const unsigned char salt[16]    = "FEDCBA987654321";

    // MD5 Demo
    unsigned char md5Out[16]{ 0 };
    md5Encode(message, sizeof(message) - 1, md5Out);
    printf("MD5: ");
    for (int i = 0; i < sizeof(md5Out); i++) {
        printf("%02X ", md5Out[i]);
    }
    printf("\n");

    // SHA Demo
    unsigned char shaOut1[SHA1_OUTLEN]{ 0 };
    sha1Encode(message, sizeof(message) - 1, shaOut1);
    printf("SHA1: ");
    for (int i = 0; i < sizeof(shaOut1); i++) {
        printf("%02X ", shaOut1[i]);
    }
    printf("\n");
    unsigned char shaOut224[SHA224_OUTLEN]{ 0 };
    sha224Encode(message, sizeof(message) - 1, shaOut224);
    printf("SHA224: ");
    for (int i = 0; i < sizeof(shaOut224); i++) {
        printf("%02X ", shaOut224[i]);
    }
    printf("\n");
    unsigned char shaOut256[SHA256_OUTLEN]{ 0 };
    sha256Encode(message, sizeof(message) - 1, shaOut256);
    printf("SHA256: ");
    for (int i = 0; i < sizeof(shaOut256); i++) {
        printf("%02X ", shaOut256[i]);
    }
    printf("\n");
    unsigned char shaOut384[SHA384_OUTLEN]{ 0 };
    sha384Encode(message, sizeof(message) - 1, shaOut384);
    printf("SHA384: ");
    for (int i = 0; i < sizeof(shaOut384); i++) {
        printf("%02X ", shaOut384[i]);
    }
    printf("\n");
    unsigned char shaOut512[SHA512_OUTLEN]{ 0 };
    sha512Encode(message, sizeof(message) - 1, shaOut512);
    printf("SHA512: ");
    for (int i = 0; i < sizeof(shaOut512); i++) {
        printf("%02X ", shaOut512[i]);
    }
    printf("\n");

    // HMAC Demo
    unsigned char hmacOut[SHA1_OUTLEN]{ 0 };
    hmacSha1(key, sizeof(key) - 1, message, sizeof(message) - 1, hmacOut);
    printf("HMAC-SHA1: ");
    for (int i = 0; i < sizeof(hmacOut); i++) {
        printf("%02X ", hmacOut[i]);
    }
    printf("\n");

    // KDF Demo
    unsigned char kdfOut[SHA1_OUTLEN]{ 0 };
    kdfHmacSha1(key, sizeof(key) - 1, salt, sizeof(salt) - 1, 520, SHA1_OUTLEN, kdfOut);
    printf("KDF-HMAC-SHA1: ");
    for (int i = 0; i < sizeof(kdfOut); i++) {
        printf("%02X ", kdfOut[i]);
    }
    printf("\n");

    // AES Demo
    unsigned char aesEcbEncrypt[16]{ 0 };
    aesAlgorithm(message, sizeof(message) - 1, key, NULL, aesEcbEncrypt, AES_MODE_ECB, AES_KEY_LEN_128, AES_PADDING_MODE_PKCS7, AES_ENC_ENCRYPT);
    printf("AES-ECB-ENCRYPT: ");
    for (int i = 0; i < sizeof(aesEcbEncrypt); i++) {
        printf("%02X ", aesEcbEncrypt[i]);
    }
    printf("\n");
    unsigned char aesEcbDecrypt[sizeof(message) - 1]{ 0 };
    aesAlgorithm(aesEcbEncrypt, sizeof(aesEcbEncrypt), key, NULL, aesEcbDecrypt, AES_MODE_ECB, AES_KEY_LEN_128, AES_PADDING_MODE_PKCS7, AES_ENC_DECRYPT);
    printf("AES-ECB-DECRYPT: ");
    for (int i = 0; i < sizeof(aesEcbDecrypt); i++) {
        printf("%02X ", aesEcbDecrypt[i]);
    }
    printf("\n");
    unsigned char aesCbcEncrypt[16]{ 0 };
    aesAlgorithm(message, sizeof(message) - 1, key, salt, aesCbcEncrypt, AES_MODE_CBC, AES_KEY_LEN_128, AES_PADDING_MODE_PKCS7, AES_ENC_ENCRYPT);
    printf("AES-CCB-ENCRYPT: ");
    for (int i = 0; i < sizeof(aesCbcEncrypt); i++) {
        printf("%02X ", aesCbcEncrypt[i]);
    }
    printf("\n");
    unsigned char aesCbcDecrypt[sizeof(message) - 1]{ 0 };
    aesAlgorithm(aesCbcEncrypt, sizeof(aesCbcEncrypt), key, salt, aesCbcDecrypt, AES_MODE_CBC, AES_KEY_LEN_128, AES_PADDING_MODE_PKCS7, AES_ENC_DECRYPT);
    printf("AES-CCB-DECRYPT: ");
    for (int i = 0; i < sizeof(aesCbcDecrypt); i++) {
        printf("%02X ", aesCbcDecrypt[i]);
    }
    printf("\n");


    // RSA Demo
    Dodecahedron::Bigint publicKey;
    Dodecahedron::Bigint privateKey;
    generateRSA(2048, publicKey, privateKey);

}
