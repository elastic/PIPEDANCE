<img width="1440" alt="Elastic Security Labs Banner Image" src="https://user-images.githubusercontent.com/7442091/234121634-fd2518cf-70cb-4eee-8134-393c1f712bac.png">

## Authors
- Daniel Stepanic ([@DanielStepanic](https://twitter.com/DanielStepanic))
- Cyril François ([@cyril_t_f](https://twitter.com/cyril_t_f))

## Overview

This repository includes a Windows client application to send commands and work with the PIPEDANCE [malware](https://www.elastic.co/security-labs/twice-around-the-dance-floor-with-pipedance). PIPEDANCE is a named pipe malware that works in a point-to-point fashion with capabilities such as:
- Command execution
- Retrieve running processes
- Enumerate directories
- Perform process injection (thread-hijacking / Heaven's Gate)
- Perform connectivity checks (HTTP, ICMP, TCP, DNS)
- Terminate processes

## Requirements

- Windows OS (Tested with two different endpoints within same network. One endpoint will run the malware sample (PIPEDANCE) and one endpoint will run the PIPEDANCE client.)
- PIPEDANCE [sample](https://malshare.com/sample.php?action=detail&hash=e5ae20ac5bc2f02a136c3cc3c0b457476d39f809f28a1c578cda994a83213887)

**Testing Advice**
  - Disable or configure the Windows firewall to allow communication over the network. 
  - Named pipes in this project are used for inter-process communication (IPC) within the local network. Ensure that the appropriate permissions/controls are configured between the machines.
  - Ensure that the user accounts or service main accounts running the PIPEDANCE server/client have the necessary permissions to access and use the named pipes. This may involve configuring the appropriate security settings and permissions in Windows.

## Disclaimer

This project should NOT be used in a production environment. This is for testing and performing research that interacts directly with malware. Any activity related to this project should be conducted inside an isolated network. 

## Getting Started

Each PIPEDANCE sample comes with a hardcoded string that serves as the pipe name and RC4 key for encryption/decryption. For our testing, we used the existing hard-coded string found in our sample.

1. Compile the files included in this repository using the CMakeLists.txt file. This project will produce the PIPEDANCE client that will allow interaction with the PIPEDANCE malware on a separate machine.
2. On one endpoint (Endpoint A), run the provided PIPEDANCE malware sample from this [link](https://malshare.com/sample.php?action=detail&hash=e5ae20ac5bc2f02a136c3cc3c0b457476d39f809f28a1c578cda994a83213887). Please note, this is malware found from a real campaign, do not execute in non-testing environment.
3. On second endpoint (Endpoint B) with the compiled client from Step 1, execute the program along with the target IP address or hostname of the machine running the PIPEDANCE malware (Endpoint A).

   `pipedance_client.exe 192.168.47.130`
   
5. Follow the command prompts in order to use each function and their respective parameters. The table below consists of the different functions and their required parameters.


## Command Handler Table

Below is the list of available commands in the PIPEDANCE client application.


| Command ID | Description                                                                                | Arguments                               |
| -----------| -------------------------------------------------------------------------------------------|-----------------------------------------|
| 0          | Stop PIPEDANCE client                                                                      |                                         |
| 1          | Terminate process by PID                                                                   | PID (ex. 9867)                          |
| 2          | Run shell command and print output                                                         | Command (ex. ipconfig)                  |   
| 4          | List files in current working directory                                                    |                                         | 
| 6          | Write file to disk                                                                         | Filename (full path), file content      |
| 7          | Get current working directory                                                              |                                         |
| 8          | Change current working directory                                                           | Folder path                             |
| 9          | List running processes                                                                     |                                         |
| 23         | Create random process with hijacked token from provided PID and inject shellcode (32bits)  | PID (token hijack), shellcode           |
| 24         | Create random process with hijacked token from provided PID and inject shellcode (64bits)  | PID (token hijack), shellcode           |
| 25         | Open process from provided PID and inject shellcode (32bits)                               | PID (thread hijack), shellcode          |
| 26         | Open process from provided PID and inject shellcode (64bits)                               | PID (thread hijack), shellcode          |
| 71         | HTTP connectivity check                                                                    | Domain (ex. google.com)                 |
| 72         | DNS connectivity check with provided DNS server IP                                         | DNS server IP                           |
| 73         | ICMP connectivity check                                                                    | ICMP server IP                          |
| 74         | TCP connectivity check                                                                     | IP, port                                |
| 75         | DNS connectivity check without DNS server                                                  |                                         |
| 99         | Disconnect pipe / exit thread                                                              |                                         |
| 100        | Terminate PIPEDANCE process / disconnect Pipe / exit thread                                |                                         |

## Detections
- [YARA - Windows.Trojan.PipeDance](https://github.com/elastic/protections-artifacts/blob/f56466f20ef3de498061ad0bef6de6ce901c4091/yara/rules/Windows_Trojan_PipeDance.yar)
- [Suspicious Windows Service Execution](https://www.elastic.co/security-labs/twice-around-the-dance-floor-with-pipedance#:~:text=Detection-,Suspicious%20Windows%20Service%20Execution](https://github.com/elastic/endpoint-rules/blob/main/rules/privilege_escalation_suspicious_services_child.toml)https://github.com/elastic/endpoint-rules/blob/main/rules/privilege_escalation_suspicious_services_child.toml)
- [NullSessionPipe Registry](https://www.elastic.co/guide/en/security/current/nullsessionpipe-registry-modification.html)
- [Potential Lateral Tool Transfer via SMB Share](https://www.elastic.co/guide/en/security/master/potential-lateral-tool-transfer-via-smb-share.html)

Hunting Query:
  
`process.name:("makecab.exe" or "typeperf.exe" or  "w32tm.exe" or "bootcfg.exe" or "diskperf.exe" or "esentutl.exe") and event.dataset: endpoint.events.network`
