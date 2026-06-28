# Evasion Tools (Hack The Box Academy) - Ghi chú

## Tổng quan

Phần **Evasion Tools** giới thiệu các công cụ **tự động làm rối
(obfuscation)** command nhằm:

-   Bypass blacklist
-   Tránh các cơ chế phát hiện dựa trên signature
-   Làm payload khó đọc đối với con người
-   Hỗ trợ vượt qua các bộ lọc trong các bài pentest hoặc Command
    Injection

Ý tưởng là thay vì tự nghĩ payload bypass, ta để công cụ tự kết hợp
nhiều kỹ thuật obfuscation.

------------------------------------------------------------------------

# 1. Bashfuscator (Linux)

Bashfuscator là công cụ tạo ra các Bash command đã được obfuscate.

Ví dụ:

Command gốc:

``` bash
cat /etc/passwd
```

Có thể được biến thành:

``` bash
"$(W0=(w \ t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{
printf %s "${W0[$Ll]}";};)"
```

Payload nhìn rất khó hiểu nhưng vẫn thực thi đúng command gốc.

## Cài đặt

``` bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```

## Sử dụng

``` bash
./bashfuscator -c "cat /etc/passwd"
```

Hoặc tạo payload ngắn hơn:

``` bash
./bashfuscator \
-c "cat /etc/passwd" \
-s 1 \
-t 1 \
--no-mangling
```

## Kiểm tra

``` bash
bash -c 'eval "<payload>"'
```

Nếu xuất ra nội dung `/etc/passwd` thì payload hoạt động.

------------------------------------------------------------------------

# 2. DOSfuscation (Windows)

Đây là phiên bản dành cho Windows.

Đặc điểm:

-   Chạy ở chế độ interactive
-   Nhập command
-   Chọn kiểu obfuscation
-   Sinh payload CMD/PowerShell

Ví dụ:

``` powershell
Invoke-DOSfuscation

SET COMMAND type C:\Users\htb-student\Desktop\flag.txt

encoding

1
```

Kết quả là một command CMD cực kỳ khó đọc nhưng vẫn thực thi đúng.

------------------------------------------------------------------------

# 3. Ý nghĩa

Các bài trước trong module dạy bypass thủ công:

-   Space bypass
-   Quote bypass
-   Environment Variables
-   Hex Encoding
-   Newline
-   Wildcard
-   Character manipulation

Đến phần này:

> Không cần tự nghĩ payload nữa, hãy để công cụ tự kết hợp hàng chục kỹ
> thuật obfuscation.

------------------------------------------------------------------------

# 4. Khi nào nên dùng?

Sử dụng khi:

-   Payload thủ công bị WAF chặn.
-   Blacklist quá nhiều ký tự.
-   Muốn thử nhiều kỹ thuật bypass nhanh.
-   Muốn tạo payload khó bị phân tích.

Không nên phụ thuộc hoàn toàn vì:

-   Không phải WAF nào cũng bị bypass.
-   Payload có thể rất dài.
-   Có thể cần chỉnh sửa lại cho phù hợp với môi trường.

------------------------------------------------------------------------

# 5. Tóm tắt

    Command Injection
            │
            ▼
    Manual Bypass
        ├─ Space bypass
        ├─ Quote bypass
        ├─ Environment Variables
        ├─ Hex Encoding
        ├─ Newline
        ├─ Wildcard
        └─ Character Manipulation
            │
            ▼
    Automated Obfuscation
        ├─ Bashfuscator (Linux)
        └─ DOSfuscation (Windows)

## Kết luận

Đây là chương giới thiệu **các công cụ tự động obfuscate command**. Mục
tiêu không phải tạo payload mới mà là **biến payload hợp lệ thành một
dạng khó phát hiện hơn**, giúp tăng khả năng vượt qua các bộ lọc trong
quá trình pentest.
