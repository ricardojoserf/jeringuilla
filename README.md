# jeringa

Tool for easy process injection

It implements:

- Process listing: By process name or process owner
- Dynamic function loading using delegates
- Payload: As input argument or using a url to download it
- Process injection via:
    - OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
