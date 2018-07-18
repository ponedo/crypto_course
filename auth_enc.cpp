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
    EVP_DigestFinal_ex(&ctx, output, &output_length);  
    EVP_MD_CTX_cleanup(&ctx);  
  
    return 0;  
}

int HmacEncode(const char* key, char * input, unsigned int input_length, unsigned char * &output, unsigned int &output_length) 
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

char *rsa_encrypt(char *input,char *path_key){

    unsigned char *p_en;
    RSA *p_rsa;
    FILE *file;
    int flen,rsa_len;

    if((file=fopen(path_key,"r"))==NULL){
        perror("open public key file error");
        return NULL;    
    }   

    if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL)
    {
        perror("Public key file format error");
        return NULL;
    } 

    flen = strlen(input);
    rsa_len = RSA_size(p_rsa);
    p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);

    if(RSA_public_encrypt(rsa_len, (unsigned char *)input, p_en, p_rsa, RSA_NO_PADDING)<0){
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return (char* )p_en;
    }

int main(int argc, char **argv)  
{

    FILE *pf = fopen(argv[1], "r");
    FILE *pf2 = fopen(argv[2], "w+");

    char ch;
    char *buf;
    unsigned char* Key_buf;
    char *EncryptData=NULL;

    char pub_key_path[32] = "pubkey.pem";
    char *rsa_enc;
    
    unsigned char password[129];
    unsigned char AESKey[AES_BLOCK_SIZE+1];
    unsigned char MACKey[AES_BLOCK_SIZE+1];
    unsigned char ivec[AES_BLOCK_SIZE];
    AES_KEY AesKey;
    
    unsigned char* mac = NULL;  
    unsigned int mac_length = 0;
    unsigned int hash_length = 0;  
    
    int file_size, pad_size, byte_num, i;

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

    EncryptData = (char *)calloc(1025, sizeof(char));  
    if(EncryptData == NULL)
    {  
        fprintf(stderr, "Unable to allocate memory for EncryptData\n");  
        exit(-1);  
    }

    OpenSSL_add_all_digests(); 

    //user input the password
    memset(password, 0x00, 129);
    printf("Please input a random password(random x)(less than 128 bytes): "); //input password(random x)
    scanf("%s", password);
    
    rsa_enc = rsa_encrypt((char *)password, pub_key_path); //rsa_encrypt password
    for (i=0; i<256; i++) //write rsa_encrypted password into the target file
        fputc(rsa_enc[i], pf2);

    //32-byte-key hashed out. Former 16 bytes for AES, latter 16 bytes for HMAC
    HashEncode((const char* )password, strlen((const char* )password), Key_buf, hash_length);
    memset(AESKey, 0x00, AES_BLOCK_SIZE+1);
    memcpy(AESKey, Key_buf, 16);
    memset(MACKey, 0x00, AES_BLOCK_SIZE+1);
    memcpy(MACKey, (Key_buf+16), 16);
    printf("\n==================Encrypting...================\n\n");
    
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

    //read file size and calculate pad size
    file_size = get_file_size(argv[1]);
    printf("\tfile_size: %d byte(s)\n", file_size);
    pad_size = AES_BLOCK_SIZE - file_size%AES_BLOCK_SIZE;
    printf("\tpad_size: %d bit(s)\n", pad_size);
    
    //write pad size into file
    fputc((unsigned char)pad_size, pf2);

    //initialize iv and write it into ciphertext
    RAND_pseudo_bytes(ivec, sizeof(ivec));
    for (i=0; i<AES_BLOCK_SIZE; i++)
        fputc(ivec[i], pf2);

    while (true)
    {
        byte_num = (file_size<=1024) ? file_size : 1024;

        memset(buf, 0x00, 1024);
        buf[1024]= '\0';  

        for (i=0; i<byte_num; i++)
        {
            ch = fgetc(pf);
            buf[i] = ch;
        }
        file_size = file_size - 1024;

        memset(&AesKey, 0x00, sizeof(AES_KEY));
        if(AES_set_encrypt_key(AESKey, 128, &AesKey) < 0) //set enc key
        {
            fprintf(stderr, "Unable to set encryption key in AES...\n");  
            exit(-1);  
        }

        //Encrypt (one buf size)
        AES_cbc_encrypt((unsigned char *)buf, (unsigned char *)EncryptData,   
            byte_num, &AesKey, ivec, AES_ENCRYPT);
        
        if (file_size <= 0) //encryption complete
        {
            for (i=0; i<byte_num+pad_size; i++)
                fputc(EncryptData[i], pf2);
            HmacEncode((const char* )MACKey, EncryptData, byte_num+pad_size, mac, mac_length); //HMAC
            for (i=0; i<mac_length; i++)
                fputc(mac[i], pf2);
            break;
        }
        else
        {
            for (i=0; i<1024; i++)
                fputc(EncryptData[i], pf2);
            for(i=0; i<AES_BLOCK_SIZE; i++) //next iv
                ivec[i] = EncryptData[1024-AES_BLOCK_SIZE+i];
            HmacEncode((const char* )MACKey, EncryptData, 1024, mac, mac_length); //HMAC
            for (i=0; i<mac_length; i++)
                fputc(mac[i], pf2);
        }
    }
    
    if (buf)
        free(buf);  
    if (EncryptData)
        free(EncryptData);  
    if (mac)
        free(mac);
    if(rsa_enc)
        free(rsa_enc);   

    fclose(pf2);
    fclose(pf);

    printf("\n================Encryption done!===============\n\n");

    exit(0);
}
