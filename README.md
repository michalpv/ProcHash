# ProcHash
Windows tool used for detecting malicious processes by hashing executable files

This program relies heavily on the OPSWAT MetaDefender Cloud API to perform hash lookups and identify malicious files.
https://metadefender.opswat.com/

# Usage
In order to use this program, you must first create an account on OPSWAT's website and obtain a unique API key. Once you have this key, define the APIKEY macro in the source file ProcHash.c with your key in string format:
```c
#define APIKEY "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

Once you have completed this step, all that's left is to compile. Here is an example command for the Visual Studio compiler:
```
cl.exe ProcHash.c
```
