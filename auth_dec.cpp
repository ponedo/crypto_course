#include <stdio.h>  
#include <string.h>  
#include <sys/types.h>  
#include <sys/stat.h>  
#include <fcntl.h>  
#include <errno.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include <openssl/aes.h>  
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>  
#include <openssl/pem.h>  
#include <openssl/evp.h>  

/****************************************************
        |+======================+| 
        || rsa_encryped password||(256 bytes)
        |+======================||

           Ciphertext structure
        |+======================+| 
        ||       pad_size       ||(1 byte)
        |+======================||
        ||          iv          ||(16 bytes)
        |+======================+|
        ||                      ||
        |+======================+|
        ||      ciphertext      ||(1024 bytes)
        |+======================+|
        ||   MAC_for_1024bytes  ||(32 bytes)
        |+======================+|
        ||      ciphertext      ||(1024 bytes)
        |+======================+|
        ||   MAC_for_1024bytes  ||(32 bytes)
        |+======================+|
        ||                      ||
        |+===     ......     ===+|
        ||                      ||
        |+======================+|
        || remaining ciphertext ||(? bytes)
        |+======================+|
        || MAC_4_last_ciphertext+|(32 bytes)
        |+======================+|
****************************************************/

unsigned long get_file_size(const char *filename) 
{ 
    struct stat buf; 
    if(stat(filename, &buf)<0) 
    { 
        return 0; 
    } 
    return (unsigned long)buf.st_size; 
}

int HashEncode(const char* input, unsigned int input_length, unsigned char * &output, unsigned int &output_length)
{  
    EVP_MD_CTX ctx;  
    const EVP_MD * md = EVP_get_digestbyname("sha256");  
    
    output = (unsigned char *)malloc(EVP_MAX_MD_SIZE);  
    memset(output, 0, EVP_MAX_MD_SIZE);  
  
    EVP_MD_CTX_init(&ctx);  
    EVP_DigestInit_ex(&ctx, md, NULL);  
    EVP_DigestUpdate(&ctx, input, input_length);  
    EVP_DigestFinal_ex(&ctx, (unsigned char *)output, &output_length);  
    EVP_MD_CTX_cleanup(&ctx);  
  
    return 0;  
}

int HmacEncode(const char* key, char * input, unsigned int input_length,  
                unsigned char * &output, unsigned int &output_length) 
{  
    const EVP_MD* engine = EVP_sha256();  
    
    output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);

    HMAC_CTX ctx;  
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, strlen(key), engine, NULL);
    HMAC_Update(&ctx, (unsigned char*)input, input_length);
    HMAC_Final(&ctx, output, &output_length);  
    HMAC_CTX_cleanup(&ctx);

    return 0;
}

char *rsa_decrypt(char *input,char *path_key){

    unsigned char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;

    if((file=fopen(path_key,"r"))==NULL){
        perror("open private key file error");
        return NULL;
    }

    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL)
    {
        perror("Private key file format error");
        return NULL;
    }

    rsa_len=RSA_size(p_rsa);
    p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);

    if(RSA_private_decrypt(rsa_len,(unsigned char *)input, p_de, p_rsa, RSA_NO_PADDING)<0)
        return NULL;

    RSA_free(p_rsa);
    fclose(file);
    return (char* )p_de;
}
 
int main(int argc, char **argv)  
{

    FILE *pf = fopen(argv[1], "r");
    FILE *pf2 = fopen(argv[2], "w+");

    char ch;
    char *buf;
    unsigned char* Key_buf;
    char *mac_buf;
    char *DecryptData=NULL;

    char pri_key_path[32] = "prikey.pem";
    char rsa_dec[257];
    
    char *password_buf;
    unsigned char password[129];
    unsigned char AESKey[AES_BLOCK_SIZE+1];
    unsigned char MACKey[AES_BLOCK_SIZE+1];
    unsigned char ivec[AES_BLOCK_SIZE];
    AES_KEY AesKey;

    unsigned char* mac = NULL;  
    unsigned int mac_length = 0;
    unsigned int hash_length = 0;  
      
    int file_size, pad_size, byte_num, i, authenticated=1; //flag: set for timing attack

    if(pf == NULL) {
        printf("opening %s failed!\n", argv[1]);
        exit(-1);
    } 

    if(pf2 == NULL) {
        printf("opening %s failed!\n", argv[2]);
        fclose(pf);
        exit(-1);
    }

    buf = (char *)calloc(1025, sizeof(char));
    if(buf == NULL)
    {  
        fprintf(stderr, "Unable to allocate memory for InputData\n");  
        exit(-1);  
    }  

    mac_buf = (char *)calloc(33, sizeof(char));
    if(mac_buf == NULL)
    {  
        fprintf(stderr, "Unable to allocate memory for InputData\n");  
        exit(-1);  
    }  

    DecryptData = (char *)calloc(1025, sizeof(char));  
    if(DecryptData == NULL)
    {  
        fprintf(stderr, "Unable to allocate memory for DecryptData\n");  
        exit(-1);  
    }

    OpenSSL_add_all_digests();

    //read rsa_encrypted password from file
    memset(rsa_dec, 0x00, 257);
    for (i=0; i<256; i++) 
        rsa_dec[i] = fgetc(pf);
    //file_size = file_size - 256 (later)
    
    password_buf = rsa_decrypt(rsa_dec, pri_key_path); //rsa_decrypt password
    memset(password, 0x00, 129);
    strcpy((char* )password, (const char* )password_buf);

    //32-byte-key hashed out. Former 16 bytes for AES, latter 16 bytes for HMAC
    HashEncode((const char*)password, strlen((const char* )password), Key_buf, hash_length);
    memset(AESKey, 0x00, AES_BLOCK_SIZE+1);
    memcpy(AESKey, Key_buf, 16);
    memset(MACKey, 0x00, AES_BLOCK_SIZE+1);
    memcpy(MACKey, (Key_buf+16), 16);
    printf("\n==================Decrypting...================\n\n");

    //print AESKey
    printf("\tAESKey: \n");
    printf("\t");
    for (i=0; i<AES_BLOCK_SIZE/2; i++)
        printf("%02x ", AESKey[i]);
    printf("\n\t");
    for (i=AES_BLOCK_SIZE/2; i<AES_BLOCK_SIZE; i++)
        printf("%02x ", AESKey[i]);
    printf("\n");
    
    //print MACKey
    printf("\tMACKey: \n");
    printf("\t");
    for (i=0; i<AES_BLOCK_SIZE/2; i++)
        printf("%02x ", MACKey[i]);
    printf("\n\t");
    for (i=AES_BLOCK_SIZE/2; i<AES_BLOCK_SIZE; i++)
        printf("%02x ", MACKey[i]);
    printf("\n\n");

    //read file_size and calculate pad size
    file_size = get_file_size(argv[1]);
    file_size = file_size - 256; //previously we have read rsa_encrypted password
    printf("\tfile_size: %d byte(s)\n", file_size);
    pad_size = (int) fgetc(pf);
    file_size = file_size - 1;
    printf("\tpad_size: %d bit(s)\n", pad_size);

    //read iv from file
    for (i=0; i<AES_BLOCK_SIZE; i++)
    {
        ch = fgetc(pf);
        ivec[i] = ch;
    }
    file_size = file_size - AES_BLOCK_SIZE;

    while (true)
    {
        byte_num = (file_size<=1024+32) ? (file_size-32) : 1024;

        memset(buf, 0x00, 1024);
        buf[1024]= '\0';  

        for (i=0; i<byte_num; i++) //read ciphertext
        {
            ch = fgetc(pf);
            buf[i] = ch;
        }
        for (i=0; i<32; i++) //read mac
        {
            ch = fgetc(pf);
            mac_buf[i] = ch;
        }
        file_size = file_size - (1024 + 32);

        HmacEncode((const char* )MACKey, buf, byte_num, mac, mac_length); //HMAC

        if(memcmp(mac, mac_buf, mac_length)!=0)
            authenticated = 0; //mac rejected

        memset(&AesKey, 0x00, sizeof(AES_KEY)); 
        if(AES_set_decrypt_key(AESKey, 128, &AesKey) < 0) //set dec key
        { 
            fprintf(stderr, "Unable to set decryption key in AES...\n");  
            exit(-1);  
        }

        //Decrypt (one buf size)

        AES_cbc_encrypt((unsigned char *)buf, (unsigned char *)DecryptData,   
            byte_num, &AesKey, ivec, AES_DECRYPT); 
        
        if (file_size <= 0) //decryption complete
        {
            for (i=0; i<byte_num-pad_size; i++)
                fputc(DecryptData[i], pf2);
            break;
        }
        else
        {
            for (i=0; i<1024; i++)
                fputc(DecryptData[i], pf2);
            for(i=0; i<AES_BLOCK_SIZE; i++) //next iv
                ivec[i] = buf[1024-AES_BLOCK_SIZE+i];
        }
    }

    if (buf)
        free(buf);  
    if (mac_buf)
        free(mac_buf);  
    if (DecryptData)
        free(DecryptData); 

    fclose(pf2);
    fclose(pf);

    if (!authenticated)
    {
        pf2 = fopen(argv[2], "w+");
        fclose(pf2);
        printf("\n======MAC rejected! Authentication failed!=====\n");
    }
    else
    {
        printf("\n====MAC authenticated. Decryption complete.====\n\n");
    }

    exit(0);
}
