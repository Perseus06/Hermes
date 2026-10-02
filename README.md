Hermes:
---------

<b>Hermes</b> is a cybersecurity CLI tool for extracting strings from the memory of a process. The user gives Hermes the PID of a process, and Hermes extract all the strings it can find in the memory of that process. Because all the PE file is loaded to the memory, Hermes cannot miss any strings from the file, so it's enough to use only Hermes.

Pay attention that the tool is adjusted for the <b>memory of Windows only</b>, and uses the Windows API. 


### Usage

Very simple usage. make sure to run the malware in any windows machine you would like, and from CMD run Hermes this way:

Hermes.exe (PID of malware's process)

for example: Hermes 5112

That's it. Now Hermes will make sure to give you all the strings it can find in the memory.

For more advanced search, you can state the minimal length of string you would like to be extracted by Hermes. If you would like to watch only strings that contains at least 12 chars, you can do it with defining minimal length as 12 (that includes 12). The minimal length is defined using the -n argument:

Hermes.exe -n (minimal length of string) (PID of malware's process)

for example: Hermes.exe -n 12 5112


### The advantage of Hermes over most strings extraction tools

Most strings extractors search for strings in the executable of the malware. As a result, they face a major problem when the executable has anti-analysis mechanisms like packing, obfuscation, encryption .etc. Those anti-analysis mechanisms change the look of the executable, and make the strings look... not like strings. Whether it's because of compression (packing) or the strings are encrypted, the strings are not readable in this state.

Hermes gives a superior solution for this obstacle - extraction from memory. While the PE file can has anti-analysis mechanisms as many as the attacker can choose, all those anti-analysis mechanisms are relevant for the disk only. When loaded to memory, the mechanisms make sure to change the PE file back to it's original state, because any change in the file will prevent from the CPU to execute the instruction in the file (the CPU cannot understand the PE file if it looks different).

So, if we know for sure that in the memory all the malwares will show their true form, extraction from the memory should work great - and Hermes proves it.


### Hermes - behind the scenes

There is a constant sequence of actions Hermes has to do in order to execute the strings from a process.

#### 1. Making sure the process exists:

Firstly, Hermes checks if the PID you gave it is a PID of an existing process in the machine. Hermes iterates over the Active process links (doubly linked list of processes) in order to scan all the existing processes in the system, and checks if one of those processes has the given PID. If a process with the given PID was found, Hermes understands this is the process and continues to the extraction. If no process with the PID was found, Hermes prints a message and stop running.

Note that processes which are hidden from the Active process links (a feature some complicated rootkits can have) are inevitable against Hermes, because Hermes won't be able to find them. This refers to drivers only, so if you are reverse engineering a .exe or .dll you should be just fine.

#### 2. Escalates to SeDebug privilege (bonus):

After Hermes sees the wanted process exists in the system, the tool will obtain the SeDebug privilege - a privilege used for getting access to any process in the memory, including those secured by the OS like winlogon.exe or svchost.exe. This allows Hermes to extract strings from many sensitive processes in the OS, but not all of them (for example lsass.exe is more secured and Hermes cannot extract strings from it). It's considered a bonus only, because Hermes doesn't has to achieve the SeDebug. It's not necessary, just a bonus for extracting strings from sensitive processes.

Note that for obtaining the SeDebug Hermes has to be executed with <b>administrator</b> privileges. If Hermes is executed without admin privileges the obtaining of the SeDebug will fail, but again it's totally fine.

The code for getting this privilege is constant, any program that wishes for the SeDebug privilege should run this exact code, so it's nothing unique of Hermes. You can copy it and use it for your own needs.



#### 3. Mapping the memory of the process:

Now Hermes has everything it needs - the PID of a process and the SeDebug (if obtained), so it's ready for the beginning of extraction. Hermes gets access to the memory process (handle with PROCESS\_VM\_READ). After that, it maps the memory of the process using the VirtualQueryEX() function. Using VirtualQueryEX(), Hermes can get the address space of each memory region in the memory of the process. Hermes creates some kind of iteration over the memory regions, as it starts from the first region and each time continues to the next one. Each memory region goes through an analysis process (explained in the next levels).

Note: memory region is a slice from the memory that has the same attributes and permissions. Do not confuse it with memory page which is 4KB slice - memory regions are seperated by attributes and permissions, and their size is different (and mostly larger than one page only).





#### 4. Reading single memory region:

Firstly, Hermes checks if the memory region is committed, which means the process actually using this memory region and saved data in it. If it is committed, Hermes will read the whole memory region using ReadProcessMemory() function. All the data from the memory region will be pushed to algorithm that can extract strings from large buffer of data.


#### 5. Strings extraction:

At this point Hermes is finally not working directly with memory, and already holds the data from the memory in a temporary buffer. Hermes uses an algorithm that reads this data saved in the buffer, and searches strings in it based on the minimal string length given (if non given, default length is 5). Each time the algorithm finds a string it will be printed to terminal.


Well, that's it. Levels 4 and 5 will happen over and over again for each memory region in the memory of the process. So Hermes scans the whole memory of the process, activate the algorithm for strings extraction on each memory region and print the detected strings.