# Tmux Cheat Sheet — Các lệnh hay dùng

> **Quy tắc chung:** Mọi tổ hợp phím trong tmux đều theo cấu trúc:
> **Nhấn `Ctrl + B` (prefix) → THẢ RA → rồi mới nhấn phím lệnh tiếp theo.**
> Không giữ Ctrl xuyên suốt cả 2 phím — đây là lỗi phổ biến nhất khiến lệnh "không ăn".

---

## 1. Lệnh chạy ngoài tmux (từ terminal thường)

Đây là các lệnh gõ trực tiếp vào shell, **trước khi** vào tmux hoặc để quản lý session từ bên ngoài.

| Lệnh | Giải thích dễ hiểu |
|---|---|
| `tmux` | Mở 1 session tmux mới, không đặt tên (tmux tự đặt số 0, 1, 2...) |
| `tmux new -s ten` | Mở session mới và **đặt tên riêng** là `ten` — nên dùng cách này để dễ nhớ, dễ quay lại |
| `tmux ls` | Liệt kê tất cả session đang chạy (đang mở, kể cả cái bạn đã detach) |
| `tmux attach -t ten` | Quay lại (attach) vào session tên `ten` đã tồn tại |
| `tmux a -t ten` | Viết tắt của lệnh trên (`a` = attach) |
| `tmux kill-session -t ten` | Xóa hẳn session tên `ten` (mất luôn, không khôi phục được) |
| `tmux kill-server` | Xóa **toàn bộ** mọi session tmux đang chạy trên máy |
| `unset TMUX` | Xóa biến môi trường đánh dấu "đang ở trong tmux" — dùng khi bị cảnh báo *nested session* |

---

## 2. Quản lý Session (phiên làm việc)

| Phím tắt | Giải thích dễ hiểu |
|---|---|
| `Ctrl+B` , `d` | **Detach** — thoát ra ngoài nhưng session vẫn chạy nền (không mất gì cả) |
| `Ctrl+B` , `$` | Đổi tên session hiện tại |
| `Ctrl+B` , `s` | Mở danh sách các session để chọn chuyển qua session khác |
| `Ctrl+B` , `(` | Chuyển tới session trước đó |
| `Ctrl+B` , `)` | Chuyển tới session kế tiếp |

---

## 3. Quản lý Window (giống như "tab" trong trình duyệt)

| Phím tắt | Giải thích dễ hiểu |
|---|---|
| `Ctrl+B` , `c` | Tạo 1 window (tab) mới |
| `Ctrl+B` , `,` | Đổi tên window hiện tại (rất nên làm để dễ phân biệt các tab) |
| `Ctrl+B` , `n` | Chuyển sang window kế **tiếp** (next) |
| `Ctrl+B` , `p` | Chuyển sang window **trước** (previous) |
| `Ctrl+B` , `0` → `9` | Nhảy thẳng tới window có số thứ tự tương ứng |
| `Ctrl+B` , `w` | Xem danh sách toàn bộ window dạng menu để chọn |
| `Ctrl+B` , `&` | Đóng (kill) window hiện tại — sẽ hỏi xác nhận |

---

## 4. Quản lý Pane (chia nhỏ màn hình trong 1 window)

| Phím tắt | Giải thích dễ hiểu |
|---|---|
| `Ctrl+B` , `Shift+%` | Chia đôi pane theo **chiều dọc** (2 pane cạnh nhau trái–phải) |
| `Ctrl+B` , `"` | Chia đôi pane theo **chiều ngang** (2 pane xếp trên–dưới) |
| `Ctrl+B` , `o` | Nhảy sang pane **kế tiếp** theo thứ tự |
| `Ctrl+B` , `↑ ↓ ← →` | Di chuyển sang pane theo đúng **hướng mũi tên** |
| `Ctrl+B` , `x` | Đóng pane hiện tại (hỏi xác nhận trước khi đóng) |
| `Ctrl+B` , `z` | **Zoom** — phóng to pane hiện tại full màn hình; bấm lại lần nữa để thu nhỏ về như cũ |
| `Ctrl+B` , `Alt+C` | Xóa sạch lịch sử hiển thị (clear) của pane hiện tại |
| `Ctrl+B` , giữ `Ctrl` + `↑↓←→` | Thay đổi **kích thước** pane theo hướng mũi tên |

---

## 5. Ghi log & Chụp màn hình (cần cài plugin `tmux-logging`)

| Phím tắt | Giải thích dễ hiểu |
|---|---|
| `Ctrl+B` , `Shift+P` | Bật/tắt ghi log pane hiện tại ra file (mọi lệnh + output sẽ được lưu) |
| `Ctrl+B` , `Alt+Shift+P` | Ghi log **hồi tố** — lưu lại nội dung đã có sẵn trong buffer, dùng khi quên bật log từ đầu |
| `Ctrl+B` , `Alt+P` | Chụp (screen capture) đúng nội dung của **riêng pane hiện tại** ra file, không lẫn pane khác |

---

## 6. Chế độ gõ lệnh trực tiếp (dùng khi không nhớ tổ hợp phím, hoặc phím tắt bị chặn)

Thay vì nhớ ký hiệu `%`, `"`..., bạn có thể gõ thẳng câu lệnh:

| Bước | Thao tác |
|---|---|
| 1 | Nhấn `Ctrl+B`, thả ra |
| 2 | Nhấn `:` (dấu hai chấm) — một dòng lệnh sẽ hiện ở cuối màn hình |
| 3 | Gõ lệnh cần dùng, ví dụ: `split-window -h` (chia dọc) hoặc `split-window -v` (chia ngang), hoặc `detach` (thoát ra) |
| 4 | Nhấn `Enter` |

Cách này **không phụ thuộc layout bàn phím hay ký hiệu đặc biệt**, nên dùng khi tổ hợp phím thường không ăn.

---

## 7. Thoát khỏi tmux — 2 cách khác nhau, cần phân biệt rõ

| Muốn làm gì | Cách làm | Kết quả |
|---|---|---|
| Thoát tạm, giữ session chạy nền | `Ctrl+B` , `d` | Về lại dấu nhắc shell bình thường, session vẫn còn, sau này `tmux attach -t ten` để vào lại y nguyên |
| Thoát hẳn, không cần giữ nữa | Gõ `exit` hoặc nhấn `Ctrl+D` trong pane | Nếu là pane cuối cùng, **session bị xóa luôn**, không quay lại được |

---

## 8. Cài Tmux Logging (thiết lập một lần)

```bash
# 1. Clone Tmux Plugin Manager về thư mục home
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm

# 2. Tạo file cấu hình
touch ~/.tmux.conf
```

Nội dung file `~/.tmux.conf`:
```
# Danh sách plugin
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# (Tùy chọn) tăng bộ nhớ scrollback để log hồi tố không bị mất dữ liệu cũ
set -g history-limit 50000

# Khởi tạo plugin manager (luôn để dòng này ở CUỐI file)
run '~/.tmux/plugins/tpm/tpm'
```

```bash
# 3. Nạp cấu hình (chỉ cần khi đang ở trong 1 session tmux)
tmux source ~/.tmux.conf

# 4. Mở session mới rồi cài plugin bằng phím tắt
tmux new -s setup
```
Trong session: nhấn `Ctrl+B`, thả ra, nhấn `Shift+I` (chữ I hoa) → tmux sẽ tự tải và cài plugin, đợi ~5 giây là xong.

---

## 9. Quy trình thực hành đề xuất (luyện tay theo thứ tự)

1. `tmux new -s lab` → tạo session tên "lab"
2. `Ctrl+B` , `Shift+%` → chia pane theo chiều dọc
3. `Ctrl+B` , `o` → nhảy sang pane bên cạnh, gõ thử 1 lệnh
4. `Ctrl+B` , `Shift+P` → bật ghi log, gõ vài lệnh, rồi `Ctrl+B` , `Shift+P` lần nữa để tắt log
5. `Ctrl+B` , `d` → detach ra ngoài
6. `tmux ls` → kiểm tra thấy session "lab" vẫn còn chạy nền
7. `tmux attach -t lab` → quay lại y nguyên trạng thái lúc detach
8. Xong việc thật sự → gõ `exit` ở từng pane để đóng hẳn session

---

## 10. Các lỗi thường gặp

| Hiện tượng | Nguyên nhân | Cách xử lý |
|---|---|---|
| Gõ `Ctrl+B` rồi phím lệnh nhưng không có gì xảy ra | Đang giữ Ctrl xuyên suốt thay vì thả ra giữa 2 phím; hoặc phím bị RDP/VNC chặn mất | Thả tay hẳn sau khi nhấn `Ctrl+B`, thử lại; nếu vẫn không được, dùng chế độ gõ lệnh (`Ctrl+B` rồi `:`) ở mục 6 |
| `sessions should be nested with care, unset $TMUX to force` | Đang cố `tmux attach` từ **bên trong** 1 session tmux khác | Detach session hiện tại trước (`Ctrl+B` , `d`) rồi mới attach; hoặc `unset TMUX` nếu cố tình muốn lồng |
| Copy/paste giữa 2 pane bị lẫn nội dung | Copy thủ công bằng chuột sẽ dính cả pane bên cạnh | Dùng `Ctrl+B` , `Alt+P` để chụp đúng nội dung riêng của pane đang đứng |
| Log hồi tố bị thiếu dữ liệu cũ | `history-limit` mặc định quá thấp, buffer bị tràn | Thêm dòng `set -g history-limit 50000` vào `~/.tmux.conf` |
