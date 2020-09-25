// Written by Michael Pavle
#include <windows.h>
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
	printf("[-] %s; Error %d\n", errInfo, err); // Print system error code supplied by GetLastError()
	return err;
}

int main() {
	DWORD idProcList[1024]; // Expand buffer if necessary (Not easy to predict needed size)
	DWORD cbNeeded;
	// Populate idProcList and verify no error occurred
	if (!EnumProcesses(idProcList, sizeof(idProcList), &cbNeeded)) {
		return printErr("Failed to enumerate processes");
	}
	// Check that cbNeeded is equal to the size of idProcList; if so, make new buffer using malloc of size cbNeeded + 10? (To ensure that no process is overlooked)
	for (int i = 0; i < (cbNeeded / sizeof(DWORD)); i++) { // cbNeeded will never exceed the size of idProcList, no bounds checking is required (EnumProcesses is safe)
		// Attempt to grab process handle on each id in idProcList
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, idProcList[i]);
		if (hProc != NULL) {
			// Get process information and location of the executable
			// https://stackoverflow.com/questions/4000877/how-can-i-get-the-current-instances-executable-file-name-from-native-win32-c
			// GetModuleFileNameEx - Grabs file path of executable process - https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa
			char filePath[256];
			if (GetModuleFileNameEx(hProc, 0, filePath, sizeof(filePath)) == 0) {
				printErr("Failed to get file path");
			}
			printf("[+] Process ID %d executable located at: %s\n", idProcList[i], filePath);
		}
		CloseHandle(hProc);
	}
	getch();
	return 0;
}

/*
TODO LIST:
Compute SHA256 hash/checksum of located executable and ask VirusTotal API for previous scan information
	- https://stackoverflow.com/questions/13256446/compute-md5-hash-value-by-c-winapi
	- https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--creating-an-md-5-hash-from-file-content?redirectedfrom=MSDN
	- If no file matching the hash was previously scanned, suspend process and ask user to scan file themselves.
If malicious process is found, suspend it? (ensure proper process access privileges have been set) TerminateProcess.
^ Create separate thread for doing this so main loop continues
^ https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
*/

// VS Compiler Cmd line: cl OpenProcess.c /link Psapi.lib Advapi32.lib