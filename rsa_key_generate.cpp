#include <stdio.h>  
#include <stdlib.h>  
#include <openssl/rsa.h>  
#include <openssl/pem.h>   

int main()  
{  
    FILE *Private_key_file;  
    FILE *Public_key_file;  
  
    Private_key_file = fopen("./prikey.pem", "w+");  
    Public_key_file  = fopen("./pubkey.pem", "w+");  
  
    RSA *rsa = RSA_generate_key(1024, 65537, NULL, NULL);  
    PEM_write_RSAPrivateKey(Private_key_file, rsa, NULL, NULL, 0, NULL, NULL);  
    PEM_write_RSA_PUBKEY(Public_key_file,rsa);  
    RSA_free(rsa);  
  
    fclose(Private_key_file);  
    fclose(Public_key_file);  
      
    return 0;
}
