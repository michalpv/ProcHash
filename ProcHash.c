// Written by Michael Pavle
#include <windows.h>
#include <wincrypt.h>
#include <psapi.h>
#include <stdio.h>
/*
Necessary functions:
EnumProcesses - https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses
OpenProcess - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
GetProcessInformation - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessinformation
*/

DWORD printErr(char *errInfo) {
	DWORD err = GetLastError();
	printf("[-] %s; Error %x\n", errInfo, err); // Print system error code supplied by GetLastError()
	return err;
}

char *getSha256Hash(char *filePath) { // Will return a NULL pointer if failed
	// MSDN Example: https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	// Get cryptographic service provider (CSP) context
	//if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { // PROV_RSA_FULL DOES NOT support MD5 and SHA-2 hashing
	//^ Error code 0x80090008 - https://stackoverflow.com/questions/25822745/using-sha2-512-calg-sha-512-on-windows-7-returns-invalid-algorithm-specified
	if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { // PROV_RSA_AES supports MD5 and SHA-2 hashing
		//^ https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
		printErr("Couldn't create cryptographic context");
		return NULL;
	}
	HCRYPTKEY hKey = 0; // Avoid differing type warnings for CryptCreateHash (don't just pass 0)
	if (!CryptCreateHash(hProv, CALG_SHA_256, hKey, 0, &hHash)) { // SHA-256 > MD5
		CryptReleaseContext(hProv, 0);
		printErr("Couldn't create CSP hash object");
		return NULL;
	}
	// Get file handle and read content
	HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL); // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
	if (hFile == INVALID_HANDLE_VALUE) {
		printErr("Failed to open file handle");
		return NULL;
	}
}

void procHandler(DWORD procID) {
	// Attempt to grab process handle on each id in idProcList
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProc != NULL) {
		// Get process information and location of the executable
		// https://stackoverflow.com/questions/4000877/how-can-i-get-the-current-instances-executable-file-name-from-native-win32-c
		// GetModuleFileNameEx - Grabs file path of executable process - https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa
		char filePath[256];
		if (GetModuleFileNameEx(hProc, 0, filePath, sizeof(filePath)) == 0) {
			printErr("Failed to get file path");
		}
		printf("[+] Process ID %d executable located at: %s\n", procID, filePath);
		getSha256Hash(filePath); // Test
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

/*
TODO LIST:
Compute SHA256 hash/checksum of located executable and ask VirusTotal API for previous scan information
	- https://stackoverflow.com/questions/13256446/compute-md5-hash-value-by-c-winapi
	- https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content?redirectedfrom=MSDN
	- If no file matching the hash was previously scanned, suspend process and ask user to scan file themselves on VirusTotal.
If malicious process is found, suspend it? (ensure proper process access privileges have been set) TerminateProcess.
^ Create separate thread for doing this so main loop continues
^ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
*/

// VS Compiler Cmd line: cl OpenProcess.c /link Psapi.lib Advapi32.lib