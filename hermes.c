#include <stdio.h>
#include <windows.h>
#include <tlHelp32.h>
#include <string.h>


// constants
#define DEBUG_PRIVILEGE_NAME "SeDebugPrivilege"
#define STRING_MAX_LENGTH 4096


/* function for finding the Name of the process.
   The function iterates over the active process links list, and findes a process with the PID given as argument. */
int GetProcessName(unsigned int GivenPID)
{
	// receiving a handle to a snapshot of all processes running in the system.
	HANDLE Snapshot;
	Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// if an error occured and the snapshot handle is inavlid, stop the program.
	if (Snapshot == INVALID_HANDLE_VALUE)
	{
		printf("Could not get access to the active process links for finding the process.\nerror code: %d\n\n", GetLastError());
		return -1;
	}

	/* iterating over the active process links in order to find the process.
	   notice that all the iteration is based on wchar and not char. had to do it because of visual studio's configuration, it does no affect the program at all.*/
	PROCESSENTRY32W CurrentProcessInfo;
	CurrentProcessInfo.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(Snapshot, &CurrentProcessInfo);
	while (Process32NextW(Snapshot, &CurrentProcessInfo))
	{
		// if the function finds a process that it's PID is the given PID, we found the specified process.
		if (CurrentProcessInfo.th32ProcessID == GivenPID)
		{
			printf("\nProcess was found - %ls (PID: %d).\n", CurrentProcessInfo.szExeFile, GivenPID);
			return 0;
		}
	}

	// in case process with the given PID could not be found in the system, the function returns -1.
	printf("\nERROR - could not find a process with the PID %d.\n\n", GivenPID);
	return -1;
}



// function for getting SeDebug privilege.
int GetSeDebug()
{
	// get a handle to the program process (memorings)
	int memoringsPID, IsSucceeded;
	memoringsPID = GetCurrentProcessId();
	HANDLE memoringsHandle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, memoringsPID);
	if (memoringsHandle == INVALID_HANDLE_VALUE || memoringsHandle == NULL)
	{
		return -1;
	}

	// get handle to the token of the memorings process.
	HANDLE memoringsToken;
	IsSucceeded = OpenProcessToken(memoringsHandle, TOKEN_ADJUST_PRIVILEGES, &memoringsToken);
	if (IsSucceeded == 0)
	{
		return -1;
	}

	// define the SeDebugPrivilege. with this privilege the program can acheive SYSTEM.
	LUID_AND_ATTRIBUTES DebugPrivilege;
	IsSucceeded = LookupPrivilegeValueA(NULL, DEBUG_PRIVILEGE_NAME, &(DebugPrivilege.Luid));
	if (IsSucceeded == 0)
	{
		return -1;
	}
	DebugPrivilege.Attributes = SE_PRIVILEGE_ENABLED;

	// get SeDebugPrivilege to the memorings process.
	TOKEN_PRIVILEGES NewPrivileges;
	NewPrivileges.PrivilegeCount = 1;
	NewPrivileges.Privileges[0] = DebugPrivilege;
	IsSucceeded = AdjustTokenPrivileges(memoringsToken, 0, &NewPrivileges, 0, NULL, NULL);
	if (IsSucceeded == 0)
	{
		return -1;
	}
	return 0;
}


// funtion that scannes a string found in memory and checks if all the chars in the string are printable.
// only if all chars are printable the string will be printed. this is for filtering junk unprintable strings.
void PrintIfNotJunk(char TempString[STRING_MAX_LENGTH])
{
	int StringLength = strlen(TempString);
	int i;
	int AmountOfRealChars=0;
	unsigned char CurrentChar;

	// iterate over each char in the string.
	for (i=0; i<StringLength; i++)
	{
		// get the value of the current char.
		CurrentChar = (unsigned char)TempString[i];

		// check if the value of the char is between 32-127 - the range of the printable chars in the ASCII table.
		if ((CurrentChar>=32) && (CurrentChar<=127))
		{
			// if the char is printable, increase by 1 the amount of real chars.
			AmountOfRealChars++;
		}
	}

	// print the string to the user only if all the chars in the string are printable.
	// this is for filtering the junk unprintable strings.
	if (AmountOfRealChars >= StringLength)
	{
		printf("%s\n", TempString);
	}
}


// function that receives a memory region readen from the process memory and try to find strings in it. Each string found is printed to terminal.
void ExtractStringsFromMemoryRegion(char * RegionData, SIZE_T RegionSize, int StringMinimalLength)
{
    int i, PrevTerm, j, TempStringIndex, AmountOfPrintableChars, CharIndex, StringLength;
	char TempString[STRING_MAX_LENGTH];
	unsigned char CurrentChar;
    PrevTerm=0;
    // iterate over each char in the page.
    for (i=0; i<RegionSize-1; i++)
    {
        // check if the current char is null terminator. if it is, it means everything between this and the last null terminator is a single string.
        if(RegionData[i]=='\0')
        {
			// define the length of the current string as the distance (substraction) between the current and previous null terminators.
			StringLength = i-PrevTerm;

			// check the length of the string (the distance between the current and previous null terminators).
			// the length should be longer then the minimal length and shorter then MAX_STRING_LENGTH (4096).
			// only if the length is valid an analysis will occurr on the string.
			if ((StringLength >= StringMinimalLength) && (StringLength<STRING_MAX_LENGTH))
			{
				// to print the string found, save each char between the previous null terminator to the current null terminator in TempString variable.
				for (j=PrevTerm; j<i; j++)
				{
					// calculate the index in TempString of the current char. The index is the substraction of j-PrevTerm, because PrevTerm is the entry point of the current string.
					TempStringIndex = j-PrevTerm;

					// insert the current char from the page to the string in it's correct index.
					TempString[TempStringIndex] = RegionData[j];
				}

				// for filtering strings containing too many gibbrish shit chars, the program does filtering.
				// PrintIfNotJunk() checks the string and prints it only if there are not to many gibbrish chars in it.
				PrintIfNotJunk(TempString);
				// clean TempString for the next string to be found.
				memset(&TempString, 0, TempStringIndex);
			}
            // update the previous null terminator to be the current null terminator, for the next string the program will find.
            PrevTerm = i+1;
        }
    }
}


// function that receives process handle, and reads each region from the memory of the process.
// region = part of a process memory. the permissions user has over all the bytes in a region are identical, which means i need to find regions that are all readable and scan each one of them.
void AnalyzeProcessMemory(HANDLE ProcessHandle, int StringMinimalLength)
{
	// create variables for the regions iteration in the memory.
	MEMORY_BASIC_INFORMATION MemoryRegionInfo;
	SIZE_T BytesReturnedToMemoryInfo;
	LPVOID CurrentRegionBaseAddress = 0;

	// create variables for the reading of a memory region.
	int Error;
	char* RegionData;

    // query each region in the memory of the process, and save the results in MemoryInfo struct. The loop will end when no regions left.
	while (BytesReturnedToMemoryInfo = VirtualQueryEx(ProcessHandle, CurrentRegionBaseAddress, &MemoryRegionInfo, sizeof(MemoryRegionInfo)))
	{
        // if VirtualQueryEx() returned 0, it means it could not resolve the current region, so it's definitely not a readable one.
		// if the memory region is not commited it means there is no data from the PE inside it.
		if ((BytesReturnedToMemoryInfo > 0) && (MemoryRegionInfo.State == MEM_COMMIT))
		{
			//printf("base address: %lu, size: %lu\n", MemoryRegionInfo.BaseAddress, MemoryRegionInfo.RegionSize);
			
			// define the base address for the region (start of region) based on the output of VirtualQueryEx().
			CurrentRegionBaseAddress = MemoryRegionInfo.BaseAddress;
			
			// allocate memory in the size of the current region, in order to contain the whole region data.
			RegionData = malloc(MemoryRegionInfo.RegionSize+1);

			// try to read the page and save it in 'RegionData'.
			// if reading the page failed (returned zero), print error code.
			// else, if reading the page succeeded (returned non-zero), try to extract strings from it using ExtractStringsFromMemoryPage().
			if (ReadProcessMemory(ProcessHandle, MemoryRegionInfo.BaseAddress, RegionData, MemoryRegionInfo.RegionSize, NULL) == 0)
			{
				Error = GetLastError();
				if (Error==299)
				{
					//printf("This region could not be analyzed by ReadProcessMemory(), the problem is in the region.\n");
				}
				else
				{
					printf("An unsuspected error occured: %d\n", Error);
				}
			}
			else
			{
				// if got here, it means the memory region was successfully readen!!
				// now, the program will try to extract strings from this region, using ExtractStringsFromMemoryRegion().
				ExtractStringsFromMemoryRegion(RegionData, MemoryRegionInfo.RegionSize, StringMinimalLength);
			}
			// free the allocated memory for the region. In the next iteration, a new memory chunk  will be allocated for the new region.
			free(RegionData);
		}

		// update the base address to the base address of the next region in the process memory, so in the next iteration the next region will be analyzed.
		CurrentRegionBaseAddress = (LPVOID)((DWORD_PTR)CurrentRegionBaseAddress + MemoryRegionInfo.RegionSize);
	}
}


int main(int argc, char* argv[])
{
	// arguments parsing for executing memorings properly.
	int GivenPID, StringMinimalLength;

	// no PID was given - the program cannot be executed.
	if (argc<2)
	{
		printf("\nERROR - no PID was given as argument.\nUsage: memorings.exe <PID of remote process> (for example: memorings.exe 1462).\n\n");
		exit(1);
	}

	// the user did not choose a minimal length of string, so setting 5 bytes as default length.
	if (argc==2)
	{
		StringMinimalLength = 5; // default size
		GivenPID = atoi(argv[1]);
	}

	// the user did choose a minimal length of string, so setting the minimal length of string correctly.
	else
	{
		if (strcmp(argv[1], "-n")==0)
		{
			StringMinimalLength = atoi(argv[2]);
			GivenPID = atoi(argv[3]);
		}
		else if (strcmp(argv[2], "-n")==0)
		{
			StringMinimalLength = atoi(argv[3]);
			GivenPID = atoi(argv[1]);
		}
		else
		{
			printf("\nERROR - could not parse the given arguments.\n\nUsage: memorings.exe (-n <string minimal length>) <PID of process>.\n\nExamples:\nmemorings.exe 11448\nmemorings.exe -n 6 2245\nmemorings.exe 9471 -n 12\n\n");
			exit(1);
		}
	}

	// firstly trying to get SeDebug privileges. if failed, the program can not run and therefore terminates itself.
	if (GetSeDebug() == -1)
	{
		printf("failed to get SeDebug privileges.");
	}

	// find if a process with the given PID truly exists in the system.
	int IsExist;
	IsExist = GetProcessName(GivenPID);
	if (IsExist == -1)
	{
		return -1;
	}

	// ask for handle to the process using the PID given.
	HANDLE ProcessHandle;
	ProcessHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, 0, GivenPID);
	if (ProcessHandle == NULL || ProcessHandle == INVALID_HANDLE_VALUE)
	{
		printf("\n\nProgram could not get a handle for the process.\nSeems like the program is not being executed from an admin CMD, or the chosen process is too secured by the system, and therefore strings extraction cannot be done.\n");
		return -1;
	}
	printf("got a handle over the process, starting to read the memory:\n\n");
	AnalyzeProcessMemory(ProcessHandle, StringMinimalLength);
	return 0;
}