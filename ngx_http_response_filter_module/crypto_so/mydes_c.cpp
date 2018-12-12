#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "mydes.h"

extern "C"
{
    static Des *Crypto_3des = NULL;
    void CreateSecretKey(const char* key);
    void Encrypt_3des(char *src_in, char *enc_out, int *enc_out_len);
    void Decrypt_3des(char *enc_in, char *dec_out, int *dec_out_len);

    void CreateSecretKey(const char *key)
    {
        Crypto_3des = new Des(key);
    }

    void Encrypt_3des(char *src_in, char *enc_out, int *enc_out_len)
    {
        std::string encode;
        std::string src_str(src_in);
        encode = Crypto_3des->desEncrypt(src_str);
        *enc_out_len = encode.length();
        memcpy(enc_out, encode.c_str(), encode.length());

    }

    void Decrypt_3des(char *enc_in, char *dec_out, int *dec_out_len)
    {
        std::string decode;
        std::string enc_str(enc_in);
        decode = Crypto_3des->desDecrypt(enc_str);
        *dec_out_len = decode.length();
        memcpy(dec_out, decode.c_str(), decode.length());

    }

}
