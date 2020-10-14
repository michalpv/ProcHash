/*
Written by Michael Pavle

Twitter: @_michalp
Github: @michalpv
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

struct fileInfo {
char filePath[MAX_PATH+1];
char hash[SHA2LEN*2+1]; // *2 because of string representation, +1 for null term
DWORD procID;
};

DWORD printErr(char *errInfo);
DWORD getSha256Hash(char *filePath, char *fileHash);
BOOL procHandler(DWORD procID, struct fileInfo *currentProc);
void byteToHash(BYTE *hash, DWORD hashLen, char *charHash);

DWORD printErr(char *errInfo) {
	DWORD err = GetLastError();
	printf("[-] %s; Error %x\n", errInfo, err); // Print system error code supplied by GetLastError()
	return err;
}

void byteToHash(BYTE *hash, DWORD hashLen, char *charHash) { // No need to return anything (hashLen is BYTE array length)
	CHAR rgbDigits[] = "0123456789abcdef";

	for (int i = 0; i < hashLen; i++) { // charHash length MUST be equivalent to SHA2LEN*2+1
		charHash[i*2] = rgbDigits[hash[i] >> 4];
		charHash[i*2+1] = rgbDigits[hash[i] & 0xf];
	}
	charHash[hashLen*2] = 0x0;
}

DWORD getSha256Hash(char *filePath, char *fileHash) { // Will return 0 if failed, function returns size of file hash (In the case that I change the hashing algorithm), fileHash stores hash
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
	// ^ Opening files in C:\Windows\System32 directory throws system error code ERROR_FILE_NOT_FOUND (0x2)
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
	char fileHashBytes[SHA2LEN];

	if (!CryptGetHashParam(hHash, HP_HASHVAL, fileHashBytes, &hashLen, 0)) {
		printErr("CryptGetHashParam failed");
	}
		
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	
	// Now, convert BYTE array fileHash to char[]
	byteToHash(fileHashBytes, hashLen, fileHash);

	return hashLen; // Hash length in bytes (not char array length)
}

//DWORD WINAPI procHandler(void* arg) { // ThreadProc() - CreateThread reference
	//DWORD procID = (DWORD) arg;
BOOL procHandler(DWORD procID, struct fileInfo *currentProc) {
	// Attempt to grab process handle on each id in idProcList
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProc == NULL) {
		return FALSE;
	}
	// Get process information and location of the executable
	// GetModuleFileNameEx - Grabs file path of executable process - https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa
	char filePath[MAX_PATH+1];
	if (GetModuleFileNameEx(hProc, 0, filePath, sizeof(filePath)) == 0) {
		printErr("Failed to get file path");
		return FALSE;
	}
	printf("[+] Process ID %d executable located at: %s\n", procID, filePath);
	
	char fileHash[SHA2LEN*2+1]; // Hash length of SHA256*2 for string length +1 for null terminator
	DWORD hashLen = getSha256Hash(filePath, fileHash); // Get SHA256 hash as CHAR array
	if (hashLen == 0) {
		printf("[-] Sha256Hash failed\n");
		return FALSE;
	}
	printf("[+] File Sha256 hash: %s\n", fileHash);

	strncpy(currentProc->filePath, filePath, sizeof(currentProc->filePath) - 1);
	currentProc->filePath[MAX_PATH] = 0x0;// Add null terminator manually

	strncpy(currentProc->hash, fileHash, sizeof(currentProc->hash)); // 64 bytes are expected
	currentProc->procID = procID;
	
	return TRUE;
	CloseHandle(hProc);
}

int main() {
	DWORD idProcList[1000]; // Expand buffer if necessary (Not easy to predict needed size)
	DWORD cbNeeded;

	struct fileInfo fileInfoList[1000]; // Same size as idProcList

	// Populate idProcList and verify no error occurred
	if (!EnumProcesses(idProcList, sizeof(idProcList), &cbNeeded)) {
		return printErr("Failed to enumerate processes");
	}
	// TODO: Check that cbNeeded is equal to the size of idProcList; if so, recall EnumProcesses with larger array size
	int topIndex = 0;
	for (int i = 0; i < (cbNeeded / sizeof(DWORD)); i++) { // cbNeeded will never exceed the size of idProcList, no bounds checking is required (EnumProcesses is safe)
		struct fileInfo currentProc;
		if (procHandler(idProcList[i], &currentProc)) {
			printf("fileInfo struct;\n\tPath: %s\n\tHash: %s\n\tProcID: %d\n", currentProc.filePath, currentProc.hash, currentProc.procID); // For debugging
			// Enumerate each item in fileInfoList to make sure no duplicate hash exists
			BOOL dupeExists = FALSE;
			for (int index = 0; index < topIndex; index++) {
				if (!strncmp(fileInfoList[index].hash, currentProc.hash, SHA2LEN*2)) { // Compare fileInfo.hash strings
					dupeExists = TRUE;
					break;
				}
			}
			if (!dupeExists) { // If no duplicate hash exists in fileInfo struct array, add currentProc at fileInfoList[topIndex]
				fileInfoList[topIndex] = currentProc;
				topIndex++;
			}
		}
		//CreateThread(NULL, 0, procHandler, (LPVOID) idProcList[i], 0, NULL);
	}

	// Enumerate each fileInfo struct in fileInfoList
	printf("Filtered list:\n----------------------------\n");
	for (int i = 0; i < topIndex; i++) {
		printf("File path: %s\nHash: %s\nProcID: %d\n----------------------------\n", fileInfoList[i].filePath, fileInfoList[i].hash, fileInfoList[i].procID);
	}
	getch();
	return 0;
}