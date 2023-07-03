# jeringa

Tool for easy process injection. It implements several types of process injection and uses dynamic function loading using delegates so the function names are not easiliy retrievable.
- Process listing: By process name or process owner
- Payload: As input argument or using a url to download it
- Process injection via:
    - inject-crt: OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    - inject-apc: OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC 
    - earlybird:  CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread
