Process Injection occurs when code is injected into the memory space of another running process. This allows the injected code to execute within the selected process.



Figure 1:

It is loading some libraries such as vcruntime140d.dll, ucrtbase.dll, kernelbase.dll, kernel32.dll, and ntdll.dll, and you can notice some interesting functions.



Figure 2:

You can see some interesting functions being used.

GetCurrentProcess, which returns a pseudohandle of the current process, and TerminateProcess, used to terminate a process.

GetProcAddress, commonly used in code injections to locate the addresses of functions exported from DLL libraries.

GetCurrentProcessId and GetSystemTimeAsFileTime retrieve the process ID and the system time in file format.



Figure 3:

There are several byte addition instructions (with ADD BYTE PTR), register manipulation, and memory access ([rdi], [rbp], [rsi], etc.), which suggest write and read operations, which are quite common in code injection routines or modification of a process's structures. Additionally, you can notice the presence of a conditional code (jb instructions), which may indicate flow control based on a condition or comparison, and you can also see the reference to "notepad.exe", which could be the target where the code will be injected.



Figure 4:

The call to OpenProcess is crucial in some injection techniques, as it opens the process where the code will be injected. The presence of the instruction test eax, eax after the call to OpenProcess serves to check if the function was successfully executed, indicating that the process was opened without errors and memory allocation, data writing, and execution could proceed.



Figure 5:

call qword ptr ds:[<&VirtualAllocEx>] makes a call to the VirtualAllocEx function, which allocates memory in the notepad process. This can be noted, as there are a series of data movement instructions in the registers (mov).

call qword ptr ds:[<&WriteProcessMemory>] after allocating the memory in the notepad process, this instruction calls the WriteProcessMemory function, which is responsible for writing the payload into the memory allocated in the process.

call qword ptr ds:[<&CreateRemoteThread>] calls the CreateRemoteThread function, which creates a new thread inside the notepad process to execute the injected code.



And you can see other instructions that are moving data and manipulating information in memory.



More details about Process Injection by Usman Sikander: https://offensive-panda.github.io/ProcessInjectionTechniques/



Others Malware Analysis Exercises: https://github.com/CyberSecurityUP/Malware-Analysis-Exercises



Dissecting Wndows Malware Series - Process Injection by 8kSec

https://8ksec.io/dissecting-windows-malware-series-process-injections-part-2/

