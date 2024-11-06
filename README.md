
# HookChain

## Overview

HookChain is an advanced evasion framework designed to circumvent traditional Endpoint Detection and Response (EDR) systems. By leveraging sophisticated techniques such as Import Address Table (IAT) Hooking, dynamic System Service Number (SSN) resolution, and indirect system calls, HookChain redirects Windows subsystem execution flows, effectively hiding from EDRs that monitor only common libraries like `Ntdll.dll`. This approach requires no modification to the source code of either legitimate applications or the malicious payloads.

This tool is particularly effective for threat researchers and security professionals who need to load and execute shellcode, such as payloads generated by Metasploit, in a manner that avoids detection. HookChain's advanced hooking techniques allow for seamless shellcode injection, ensuring that payloads operate stealthily within monitored environments.

## Key Features

- **IAT Hooking**: Redirects function calls at the Import Address Table, making detection by EDRs challenging.
- **Dynamic SSN Resolution**: Bypasses static analysis by resolving system call numbers dynamically, making it harder for EDRs to detect suspicious activity patterns.
- **Indirect System Calls**: Executes system calls in a way that bypasses typical monitoring mechanisms, providing a layer of invisibility to the payload.

## How It Works

1. **Shellcode Loading**: HookChain loads Metasploit-generated shellcode into memory, taking care to avoid detection by hooking at strategic points within the application’s runtime environment.
2. **Execution Flow Manipulation**: By redirecting calls through indirect methods, HookChain ensures that EDR solutions cannot easily trace the malicious payload’s behavior.
3. **Undetected Operation**: The payload is executed without triggering typical EDR alarms, remaining invisible within the target environment.

## Use Cases

- **Bypassing EDR Solutions**: HookChain has demonstrated success in evading various high-profile EDRs, including CrowdStrike, SentinelOne, Cylance, and BitDefender.
- **Security Research and Testing**: Designed for controlled environments, HookChain allows security professionals to understand the effectiveness of EDRs and adapt their defenses.

For more details and white papers on HookChain’s techniques and implementation, see the links below.

## White Paper

- [HookChain White Paper](https://arxiv.org/abs/2404.16856)