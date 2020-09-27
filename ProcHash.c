// Written by Michael Pavle
/*
Helpful resources:
Hashing w/ CryptAPI - https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content
*/
#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")

#define BUFSIZE 1024
#define SHA2LEN 32

DWORD printErr(char *errInfo) {
	DWORD err = GetLastError();
	printf("[-] %s; Error %x\n", errInfo, err); // Print system error code supplied by GetLastError()
	return err;
}

DWORD getSha256Hash(char *filePath, BYTE *fileHash) { // Will return 0 if failed, function returns size of file hash (In the case that I change the hashing algorithm), fileHash stores hash
	// MSDN Example: https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { // PROV_RSA_AES supports MD5 and SHA-2 hashing
		//^ https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
		printErr("Couldn't create cryptographic context");
		return 0;
	}
	HCRYPTKEY hKey = 0; // Avoid differing type warnings for CryptCreateHash (don't just pass 0)
	if (!CryptCreateHash(hProv, CALG_SHA_256, hKey, 0, &hHash)) { // SHA-256 > MD5
		CryptReleaseContext(hProv, 0);
		printErr("Couldn't create CSP hash object");
		return 0;
	}
	// Get file handle and read content
	HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL); // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
	if (hFile == INVALID_HANDLE_VALUE) {
		printErr("Failed to open file handle");
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return 0;
	}

	// Read from file stream in chunks and call hashing function
	BOOL result = FALSE;
	BYTE fBuffer[BUFSIZE];
	DWORD cbRead = 0;

	do {
		result = ReadFile(hFile, fBuffer, BUFSIZE, &cbRead, NULL);
		if (cbRead == 0) {
			break;
		}

		if (!CryptHashData(hHash, fBuffer, cbRead, 0)) {
			printErr("CryptHashData failed");
			CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
			return 0;
		}
	} while(result);

	CloseHandle(hFile); // No longer reading from file

	if (!result) {
		printErr("ReadFile failed");
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		//CloseHandle(hFile);
		return 0;
	}

	DWORD hashLen = SHA2LEN;
	
	if (!CryptGetHashParam(hHash, HP_HASHVAL, fileHash, &hashLen, 0)) {
		printErr("CryptGetHashParam failed");
	}
	
	// Print SHA-256 hash
	CHAR rgbDigits[] = "0123456789abcdef";
	printf("[+] SHA-256 hash of file %s is: ", filePath);
	for (DWORD i = 0; i < hashLen; i++)
	{
		printf("%c%c", rgbDigits[fileHash[i] >> 4], rgbDigits[fileHash[i] & 0xf]);
	}
	printf("\n");
		
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	
	return hashLen;
}

void procHandler(DWORD procID) {
	// Attempt to grab process handle on each id in idProcList
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProc != NULL) {
		// Get process information and location of the executable
		// GetModuleFileNameEx - Grabs file path of executable process - https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa
		char filePath[256];
		if (GetModuleFileNameEx(hProc, 0, filePath, sizeof(filePath)) == 0) {
			printErr("Failed to get file path");
		}
		printf("[+] Process ID %d executable located at: %s\n", procID, filePath);
		
		BYTE fileHash[SHA2LEN]; // Hash length of SHA256 (32 byte array)
		DWORD hashLen = getSha256Hash(filePath, fileHash); // Get SHA256 hash as BYTE array
		if (hashLen == 0) {
			printf("[-] Sha256Hash failed\n");
			return;
		}

		// To Do:


	}
	CloseHandle(hProc);
}

int main() {
	DWORD idProcList[1024]; // Expand buffer if necessary (Not easy to predict needed size)
	DWORD cbNeeded;
	// Populate idProcList and verify no error occurred
	if (!EnumProcesses(idProcList, sizeof(idProcList), &cbNeeded)) {
		return printErr("Failed to enumerate processes");
	}
	// Check that cbNeeded is equal to the size of idProcList; if so, recall EnumProcesses with larger array size
	for (int i = 0; i < (cbNeeded / sizeof(DWORD)); i++) { // cbNeeded will never exceed the size of idProcList, no bounds checking is required (EnumProcesses is safe)
		procHandler(idProcList[i]);
	}
	getch();
	return 0;
}