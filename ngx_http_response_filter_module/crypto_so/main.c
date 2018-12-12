#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <fcntl.h>

#define DES_SO_PATH "libmydes_c.so"
//#define T_D_KEY "000000000000000000000000000000000000000000000000"
#define T_D_KEY "111111111111111111111111111111111111111111111111"

#define URL_PATH "https://www.baidu.com/link?url=zAKSBMIhlv-JCgvO9TvdI6IZklLJaR3RaxHjpa639i4AwEq9G2evcfhyC3BeYYSyEmvtNBWjsnB6R01-60XufuJ9XWQCyxtX77lHBo5WlCO&wd=&eqid=d979b06e000042f50000000257a2b5fc"

void (*TU_CreateSecretKey)(const char* key);
void (*TU_Encrypt_3des)(char *src_in, char *enc_out, int *enc_out_len);
void (*TU_Decrypt_3des)(char *enc_in, char *dec_out, int *dec_out_len);

int main()
{
    void *dp = NULL;
    dp = dlopen(DES_SO_PATH, RTLD_LAZY);
    TU_CreateSecretKey = dlsym(dp, "CreateSecretKey");
    TU_Encrypt_3des = dlsym(dp, "Encrypt_3des");
    TU_Decrypt_3des = dlsym(dp, "Decrypt_3des");
    TU_CreateSecretKey(T_D_KEY);
    char enc_out[1024] = {0};
    int enc_out_len = 0;
    printf("src:%s\n", URL_PATH);
    TU_Encrypt_3des(URL_PATH, enc_out, &enc_out_len);
    printf("enc:%s\n", enc_out);
    char dec_out[1024] = {0};
    int dec_out_len = 0;
    TU_Decrypt_3des(enc_out, dec_out, &dec_out_len);
    printf("dec:%s\n", dec_out);
    dlclose(dp);

    return 0;
}
