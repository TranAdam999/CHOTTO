# Báo cáo độ chính xác CHOTTO v1.3 (Giai đoạn 2)

Đo ngày 21/10/2026 bằng `tools/eval_accuracy.py`. Chỉ đo **Tầng 2** (Tầng 1 và Tầng 3 tắt), tức khả năng
nhận ra link lừa đảo **chưa ai báo cáo** (zero-hour). Link đã có trong danh sách đen thì Tầng 1 chặn 100%.

## Dữ liệu

| Nhóm | Nguồn | Số mẫu |
| --- | --- | ---: |
| Trang .vn phổ biến | Chrome UX Report top 1 triệu (CC BY 4.0), mọi tên miền đăng ký đuôi .vn, trang chủ | 3.242 |
| Top 10.000 toàn cầu | CrUX, hạng ≤ 10.000, trang chủ | 8.296 |
| Lừa đảo nhắm VN | Phishing.Database (MIT), link đang hoạt động, đuôi .vn hoặc chứa tên thương hiệu VN | 831 |
| Lừa đảo toàn cầu | Phishing.Database, mẫu ngẫu nhiên (seed 7) | 20.000 |

Mỗi tên miền đăng ký chỉ lấy một mẫu. Link lừa đảo nằm trên tên miền phổ biến (Google Forms, Weebly...)
bị loại vì đó là việc của Tầng 1, không phải Tầng 2.

## Kết quả trên toàn bộ dữ liệu

“Bị cảnh báo” là điểm ≥ 30 (hiện màn hình đệm).

| Nhóm | v1.2 | v1.3 |
| --- | ---: | ---: |
| Báo nhầm: trang .vn phổ biến | 0,89% (29/3.242) | **0,00%** (0/3.242) |
| Báo nhầm: top 10.000 toàn cầu | 0,14% | 0,39% |
| Bắt được: lừa đảo nhắm VN | 16,5% | **24,4%** |
| Bắt được: lừa đảo toàn cầu | 11,2% | **40,6%** |
| Thời gian chấm điểm | 1,41 ms/URL | 1,15 ms/URL |

Con số 0,00% ở dòng đầu là **theo định nghĩa**, vì danh sách tên miền phổ biến được sinh từ chính CrUX.
Bảng dưới mới là con số trung thực.

## Kết quả trên tập giữ riêng (con số nên trích dẫn)

Tách 50% tên miền theo hàm băm SHA-256 (cố định, không chọn tay). Tên miền .vn trong tập giữ riêng bị
rút khỏi danh sách phổ biến, trọng số hồi quy logistic chỉ học trên nửa còn lại.

| Nhóm (tập giữ riêng) | Số mẫu | v1.2 | v1.3 |
| --- | ---: | ---: | ---: |
| Báo nhầm: trang .vn phổ biến KHÔNG có trong danh sách | 1.605 | 1,18% | 1,25% |
| Báo nhầm: top 10.000 toàn cầu | 4.180 | 0,07% | 0,26% |
| Bắt được: lừa đảo nhắm VN | 399 | 16,5% | **23,8%** |
| Bắt được: lừa đảo toàn cầu | 10.000 | 11,2% | **40,1%** |

Đọc kết quả:
- Mục tiêu “báo nhầm < 0,5% trên trang .vn phổ biến” **đạt** với 3.232 trang có trong danh sách,
  **chưa đạt** với trang .vn hợp pháp ngoài danh sách (1,25%). Gần như toàn bộ lỗi ở nhóm này là tên miền
  hợp pháp chứa tên thương hiệu: `viettelpost.vn`, `viettelmoney.vn`, `isacombank.com.vn`,
  `dangky5gviettel.com.vn`... Trọng số mạo danh thương hiệu không đổi trong v1.3 (xem dưới).
- Tỷ lệ bắt được tăng mạnh nhờ trọng số mới cho các dấu hiệu từ vựng (http, hosting miễn phí, gạch ngang,
  TLD rủi ro). Đổi lại, báo nhầm trên top toàn cầu tăng từ 0,07% lên 0,26%, vẫn dưới 0,5%.
- 60% link lừa đảo toàn cầu vẫn lọt Tầng 2: phần lớn là tên miền trông bình thường. Đó là lý do cần Tầng 1
  (danh sách đen cập nhật mỗi ngày) và Tầng 3 (tuổi tên miền).

## Hiệu chỉnh trọng số bằng hồi quy logistic

`tools/calibrate_weights.py`: mỗi dấu hiệu là một đặc trưng 0/1 (riêng từ khóa dụ dỗ là số từ khóa), học
hồi quy logistic trên nửa train, chọn ngưỡng sao cho báo nhầm trên trang .vn (train) ≤ 0,5%, rồi quy đổi hệ
số về thang điểm hiện có (ngưỡng cảnh báo 30 giữ nguyên). Mỗi điểm số vẫn gắn với một lý do tiếng Việt.

| Dấu hiệu | Số lần (train) | v1.2 | v1.3 |
| --- | ---: | ---: | ---: |
| `http` (không mã hóa) | 2.365 | 10 | 27 |
| `free_hosting` (nền tảng tạo web miễn phí) | 3.248 | 10 | 32 |
| `hyphens` (nhiều gạch ngang) | 1.666 | 10 | 18 |
| `tld` (đuôi rủi ro) | 1.316 | 15 | 18 |
| `entropy` (chuỗi ngẫu nhiên) | 1.726 | 15 | 13 |
| `digits` (nhiều chữ số) | 976 | 5 | 4 |

Chỉ dấu hiệu xuất hiện ≥ 500 lần trong tập train mới được hiệu chỉnh. Các dấu hiệu hiếm nhưng quyết định
(mạo danh thương hiệu, ký tự đồng hình, @, IP trần, link rút gọn...) xuất hiện quá ít (ví dụ `typosquat`
9 lần, `homoglyph` 0 lần) nên giữ trọng số viết tay: hồi quy với ít mẫu như vậy cho hệ số không tin được
(lần chạy thử với ngưỡng 30 mẫu cho `combosquat` = 2 điểm, rõ ràng sai).

Một lỗi phát hiện nhờ bộ đo: Public Suffix List xếp `service.gov.uk`, `gov.ru` vào mục PRIVATE nên trang
chính phủ bị gắn nhãn “hosting miễn phí”. v1.3 không gắn nhãn này cho hậu tố có nhãn `gov/govt/gob/gouv/mil`.

## Tầng 1: hiệu năng với danh sách thật

Dựng từ 392.036 tên miền của Phishing.Database: file dấu vân tay 3,1 MB, nạp lần đầu 11 ms, mỗi lần tra
(gồm `stat` kiểm tra file đổi) 29 µs. Tra 2.000 tên miền có trong danh sách: tìm thấy 1.997 (3 mục bị loại
có chủ đích vì trùng tên miền tin cậy/hậu tố công cộng). 2.000 tên miền sạch: 0 báo nhầm.

## Hạn chế của phép đo

- Mẫu hợp pháp chỉ là **trang chủ**; link thật trong Zalo có đường dẫn và tham số, nên báo nhầm thực tế
  có thể cao hơn (nhất là từ khóa dụ dỗ trong đường dẫn).
- Tập “lừa đảo nhắm VN” được chọn bằng đuôi .vn hoặc tên thương hiệu trong URL, nên dấu hiệu mạo danh
  thương hiệu được lợi trong tập này. Chưa có bộ dữ liệu lừa đảo tiếng Việt có nhãn công khai (ChongLuaDao
  không truy cập được từ môi trường đo).
- Trang hợp pháp phổ biến trên CrUX phần lớn dùng HTTPS; trang nhỏ của doanh nghiệp Việt còn dùng HTTP có
  thể bị báo nhầm nhiều hơn con số ở đây.

## Chạy lại

```bash
python tools/eval_accuracy.py --download --data .eval-data                    # tải dữ liệu (~75 MB)
python tools/eval_accuracy.py --data .eval-data --report full.md              # toàn bộ dữ liệu
python tools/eval_accuracy.py --data .eval-data --holdout 0.5 --test-split    # tập giữ riêng
python tools/calibrate_weights.py --data .eval-data --min-support 500 --l2 0.001 --out w.json
python tools/eval_accuracy.py --data .eval-data --holdout 0.5 --test-split --weights w.json
```
