# CHOTTO – Khoan đã! (v1.4.0)

Trạm kiểm soát link Zalo trên máy tính (Windows / macOS). CHOTTO đăng ký làm trình duyệt mặc định,
nhận link được bấm trong Zalo, chấm điểm rủi ro rồi mới quyết định mở thẳng hay hiện màn hình cảnh báo
có **độ trễ có chủ ý** (nút “vẫn mở” bị khóa vài giây để người dùng kịp suy nghĩ).

Từ bản 1.2, CHOTTO chạy một **agent nền** giữ sẵn bộ thẩm định trong RAM. Mỗi lần bấm link, hệ điều hành
gọi một launcher nhỏ: launcher nhận diện nguồn gọi, giao link cho agent qua kênh IPC có xác thực rồi thoát.
Link an toàn mở gần như tức thì; link đáng ngờ hiện màn hình cảnh báo ngay, phần tra tuổi tên miền chạy
nền và tự cập nhật lên màn hình.

Bản 1.3 tập trung vào **độ chính xác**, đo trên dữ liệu thật (xem `tools/` và mục “Độ chính xác”):
danh sách 3.232 tên miền .vn phổ biến để giảm báo nhầm, đường cong điểm tuổi tên miền liên tục, RDAP hỏi
thẳng nhà đăng ký, lời khuyên theo tổ hợp dấu hiệu, và Tầng 1 tra cứu hoàn toàn trong RAM, tự cập nhật
mỗi ngày.

Bản 1.4 thêm **tiện ích trình duyệt (Manifest V3) cho Zalo Web** (`chat.zalo.me`) trên Chrome, Edge và
Firefox, trong thư mục [`extension/`](extension/README.md). Tiện ích dùng **chung bộ luật và dữ liệu** với
bản Desktop; một bộ 2.521 URL dùng chung (`tests/data/engine_vectors.json`) bảo đảm hai bản cho cùng điểm,
cùng mức, cùng lý do và cùng lời khuyên.

## Yêu cầu
- Python **3.11+** (cần có `tkinter`; trên Linux: `sudo apt install python3-tk`).
- Chạy chương trình: **không cần cài thư viện ngoài**, chỉ dùng thư viện chuẩn.
- Đóng gói ra `.exe` / `.app`: `pip install -r requirements.txt` (xem file `requirements.txt`).

## Cấu trúc
```
CHOTTO/
├── main.py                   điểm vào: launcher (nhận link) / agent / cửa sổ cài đặt / lệnh CLI
├── requirements.txt          thư viện cho bước đóng gói
├── chotto/
│   ├── engine.py             ghép 3 tầng, tính điểm và quyết định mức cảnh báo
│   ├── tier1.py              Tầng 1: danh sách đen offline (dấu vân tay 64-bit trong RAM, SQLite làm gốc, cập nhật theo ETag)
│   ├── tier2.py              Tầng 2: heuristics tiếng Việt (thương hiệu giả, TLD rủi ro, từ khóa dụ dỗ...)
│   ├── tier3.py              Tầng 3: tuổi tên miền (RDAP theo IANA bootstrap ‖ WHOIS), cache SQLite 48h, timeout 1,8s
│   ├── advisor.py            AI's Advices: lời khuyên cục bộ theo tổ hợp dấu hiệu, rồi từng dấu hiệu
│   ├── caller.py             nhận diện link có xuất phát từ Zalo hay không
│   ├── platform_setup.py     đăng ký URL handler + chuyển tiếp sang trình duyệt thật
│   ├── ui.py                 giao diện Tkinter Dark Mode: màn hình đệm + cửa sổ cài đặt
│   ├── logdb.py              nhật ký quyết định (SQLite) + xuất CSV
│   ├── config.py             cấu hình người dùng, đường dẫn dữ liệu
│   ├── util.py               hàm dùng chung (tên miền đăng ký, skeleton đồng hình, Damerau, chuẩn hóa tiếng Việt...)
│   ├── service/
│   │   ├── ipc.py            kênh IPC cục bộ (Named Pipe / Unix socket) + xác thực HMAC hai chiều
│   │   ├── agent.py          giao thức launcher ↔ agent, hàng đợi link
│   │   ├── handler.py        luồng xử lý một link (chính sách an toàn, Tầng 3 chạy nền)
│   │   └── app.py            vòng đời giao diện: agent thường trú và chế độ một tiến trình
│   ├── core/
│   │   ├── url.py            bộ phân tích URL theo chuẩn WHATWG (giống trình duyệt), IDNA/UTS46, IPv4 dạng số
│   │   └── psl.py            Public Suffix List (cả phần PRIVATE như web.app, github.io)
│   └── data/
│       ├── rules.json        bộ luật v3 (thương hiệu, TLD, từ khóa, trọng số, đường cong tuổi, wrapper, nguồn danh sách đen)
│       ├── popular_vn.txt    3.232 tên miền .vn phổ biến (CrUX, CC BY 4.0), miễn chấm điểm Tầng 2
│       ├── public_suffix_list.dat   Public Suffix List (MPL-2.0, publicsuffix.org)
│       ├── confusables_ascii.json   bảng ký tự đồng hình rút từ Unicode TR39
│       └── blacklist.seed.txt   danh sách đen khởi tạo
├── extension/                tiện ích trình duyệt cho Zalo Web (xem extension/README.md)
│   ├── manifest.json         Manifest V3 (Chrome/Edge; bản Firefox sinh lúc đóng gói)
│   ├── src/engine/           engine 3 tầng viết lại bằng JavaScript, khớp 1-1 với bản Python
│   ├── src/                  service worker, content script, main-world script, kho IndexedDB, cập nhật
│   ├── src/ui/               màn hình “Khoan đã!” (Shadow DOM đóng), trang cảnh báo, trang cài đặt
│   ├── data/                 dữ liệu sinh từ chotto/data bằng tools/sync_extension_data.py
│   ├── tests/                test Node (engine, IndexedDB, cập nhật, khớp với Python)
│   └── e2e/                  test end-to-end bằng Chromium thật trên trang Zalo giả lập
├── packaging/
│   ├── build_windows.bat     đóng gói CHOTTO (PyInstaller, chế độ onedir)
│   └── macos_setup.py        đóng gói CHOTTO.app (py2app)
├── docs/BAO-CAO-DO-CHINH-XAC.md   báo cáo đo độ chính xác v1.2 → v1.3
├── tools/
│   ├── eval_accuracy.py      đo báo nhầm / tỷ lệ bắt được trên dữ liệu thật (CrUX + Phishing.Database)
│   ├── calibrate_weights.py  hồi quy logistic để hiệu chỉnh trọng số, kiểm chứng trên tập giữ riêng
│   ├── build_popular.py      sinh lại chotto/data/popular_vn.txt
│   ├── sync_extension_data.py   đồng bộ chotto/data → extension/data (--check để kiểm tra lệch)
│   ├── gen_engine_vectors.py    sinh bộ URL dùng chung cho test khớp Python ↔ JavaScript
│   └── build_extension.py    đóng gói dist/chotto-extension-{chrome,firefox}-<phiên bản>.zip
└── tests/                    151 test: engine + ca tấn công trong audit, URL, PSL, Tầng 1/3, cấu hình,
                              nhật ký, luồng xử lý link, IPC/agent/launcher, lệnh mở trình duyệt,
                              nhận diện Zalo, giao diện Tk (tự bỏ qua nếu máy không có Tk), danh sách
                              phổ biến, lời khuyên tổ hợp, RDAP bootstrap, cập nhật tăng dần,
                              dữ liệu tiện ích khớp bản Desktop, bộ URL dùng chung
```

## Chạy thử (không cần cài đặt gì)
Chạy các lệnh sau từ thư mục gốc dự án:
```bash
python -m unittest discover -s tests                          # chạy 147 test
mypy --strict main.py chotto                                  # kiểm tra kiểu (thêm --platform win32 / darwin)
python main.py check "https://vcb-digibanks.top/xac-nhan"     # xem điểm + lý do (JSON)
python main.py --force "https://vcb-digibanks.top/xac-nhan"   # xem thử màn hình cảnh báo (bỏ qua bước "có từ Zalo không")
python main.py update-blacklist                               # nạp danh sách đen thật từ mạng
python main.py agent                                          # chạy agent nền (cửa sổ terminal này giữ agent)
python main.py agent-status                                   # (terminal khác) kiểm tra agent
```

## Cài đặt
### Windows
```bash
python main.py install
```
Sau đó vào **Cài đặt ▸ Ứng dụng mặc định** và chọn **CHOTTO** cho HTTP/HTTPS.
(Windows không cho phần mềm tự đặt trình duyệt mặc định nên bước chọn này phải làm tay.)

Đóng gói:
```bash
pip install -r requirements.txt
packaging\build_windows.bat        # ra thư mục dist\CHOTTO\
```
Chép cả thư mục `dist\CHOTTO` tới chỗ cố định (ví dụ `%LOCALAPPDATA%\Programs\CHOTTO`) rồi chạy `CHOTTO.exe install`.
Bản 1.1 dùng `--onedir` thay vì `--onefile` để mỗi lần bấm link không phải giải nén lại ra `%TEMP%`.
Lệnh `install` ghi nhớ trình duyệt mặc định hiện tại (Chrome, Edge, Firefox, Cốc Cốc, Brave...) để chuyển tiếp link sang đó.

### macOS
Chạy **từ thư mục gốc dự án** (không phải `packaging/`):
```bash
pip install -r requirements.txt
python packaging/macos_setup.py py2app
```
Chép `dist/CHOTTO.app` vào `/Applications`, rồi vào **Cài đặt hệ thống ▸ Máy tính để bàn & Dock ▸ Trình duyệt web mặc định** và chọn CHOTTO.
Mở CHOTTO.app một lần và bấm **Cài làm trình duyệt mặc định** trong cửa sổ cài đặt: CHOTTO ghi nhớ trình duyệt thật và tạo LaunchAgent để tự chạy nền khi đăng nhập.

### Cửa sổ cài đặt
Chạy `python main.py` không tham số (hoặc mở `CHOTTO.app` trực tiếp) để mở cửa sổ cài đặt:
bật/tắt Tầng 3, chỉnh thời gian khóa nút “vẫn mở” (3–15 giây), bật/tắt nhật ký, cập nhật danh sách đen,
xuất nhật ký CSV, cài/gỡ handler.

## Các lệnh CLI
| Lệnh | Tác dụng |
|---|---|
| `main.py <url>` | Chế độ trình duyệt mặc định: kiểm tra link rồi mở hoặc cảnh báo |
| `main.py --force <url>` | Như trên nhưng bỏ qua bước nhận diện Zalo (để thử giao diện) |
| `main.py` | Mở cửa sổ cài đặt |
| `main.py check <url>` | In kết quả thẩm định dạng JSON |
| `main.py install` / `uninstall` | Đăng ký / gỡ đăng ký handler, bật / tắt agent tự chạy khi đăng nhập |
| `main.py agent` | Chạy agent nền (thường do hệ thống tự gọi lúc đăng nhập) |
| `main.py agent-status` / `agent-stop` | Xem agent có đang chạy / yêu cầu agent tắt |
| `main.py update-blacklist` | Tải và dựng lại danh sách đen |
| `main.py export-log <file.csv>` | Xuất nhật ký quyết định ra CSV |
| `main.py log` | In đường dẫn và 30 dòng cuối của `chotto.log` (để gỡ lỗi) |

## Cách CHOTTO quyết định
| Điều kiện | Kết quả |
|---|---|
| Link không phải từ Zalo (Word, Excel, terminal...) | Mở thẳng trình duyệt thật, không kiểm tra |
| Link không phải http/https | Từ chối, không mở |
| Link bọc (Zalo, Messenger, Google, AMP, Safe Links...) | Bóc tối đa 8 lớp rồi chấm điểm đích cuối; quá 8 lớp thì cộng điểm `nested_redirect` |
| Trùng danh sách đen (Tầng 1) ở bất kỳ lớp nào | `BLOCKED`, 100 điểm |
| Không phân tích được URL, hoặc engine lỗi | `WARN` 50 điểm (an toàn khi lỗi: không bao giờ mở thẳng) |
| Đích thuộc tên miền tin cậy, tên miền chính thức của thương hiệu, hoặc 3.232 tên miền .vn phổ biến | Không chấm điểm Tầng 2 (Tầng 1 vẫn kiểm tra; URL nhúng trong tham số vẫn bị chấm, chống chuyển hướng mở) |
| Điểm Tầng 2 trong khoảng 10–50, Tầng 3 bật, không phải IP / link rút gọn / nền tảng hosting miễn phí | Tra tuổi tên miền, điểm theo đường cong liên tục `age_curve`: 0 ngày **+50**, 7 ngày **+40**, 30 ngày **+22**, 90 ngày **+10**, 180–365 ngày **0**, 2 năm **−10** (nội suy tuyến tính giữa các mốc; không trừ nếu tên miền giả thương hiệu) |
| Tổng điểm < 30 | `SAFE`: mở trình duyệt ngay |
| 30–59 | `WARN`: màn hình đệm, nút “vẫn mở” khóa theo cấu hình (mặc định 5 giây), tối đa 4 lý do |
| ≥ 60 | `HIGH`: như trên, khóa thêm 3 giây |
| `BLOCKED` | Như trên, khóa thêm 5 giây |
| Tầng 3 cần chạy và điểm Tầng 2 đã ≥ 30 | Màn hình cảnh báo hiện **ngay**, dòng “Đang xác minh tuổi tên miền…”; khi có kết quả, điểm/lý do tự cập nhật. Mức cảnh báo chỉ tăng (khi đó thời gian khóa nút được kéo dài), không bao giờ giảm |
| Tầng 3 cần chạy và điểm Tầng 2 < 30 | Chờ Tầng 3 (tối đa 1,8 giây) rồi mới quyết định mở hay cảnh báo |
| Tầng 3 tắt hoặc tra không được | AI's Advices hiển thị lời khuyên cục bộ, ưu tiên theo kịch bản (ví dụ “giả danh Vietcombank rồi hối thúc”) |
| Giao diện cảnh báo không hiện được | Hộp thoại hệ thống báo đã chặn; link nguy hiểm **không** bị mở |

Mọi trọng số và ngưỡng nằm trong `chotto/data/rules.json`; sửa file này để chỉnh luật mà không cần đụng code.

## Độ chính xác
Đo Tầng 2 (link chưa ai báo cáo) trên dữ liệu thật, tập giữ riêng không dùng khi chỉnh luật. Chi tiết,
phương pháp và hạn chế: [`docs/BAO-CAO-DO-CHINH-XAC.md`](docs/BAO-CAO-DO-CHINH-XAC.md).

| | v1.2 | v1.3 |
|---|---:|---:|
| Báo nhầm, 3.232 trang .vn phổ biến (có trong danh sách) | 0,89% | 0,00% |
| Báo nhầm, trang .vn phổ biến KHÔNG có trong danh sách | 1,18% | 1,25% |
| Báo nhầm, top 10.000 toàn cầu | 0,07% | 0,26% |
| Bắt được, lừa đảo nhắm VN | 16,5% | 23,8% |
| Bắt được, lừa đảo toàn cầu | 11,2% | 40,1% |

## Dữ liệu và quyền riêng tư
CHOTTO lưu dữ liệu tại:

| Hệ điều hành | Thư mục |
|---|---|
| Windows | `%APPDATA%\CHOTTO` |
| macOS | `~/Library/Application Support/CHOTTO` |
| Linux | `~/.config/CHOTTO` |

Đặt biến môi trường `CHOTTO_DATA_DIR` để dùng thư mục khác (các test dùng cách này để không đụng dữ liệu thật).

Gồm `config.json`, `agent.key` (khóa xác thực IPC, chỉ người dùng hiện tại đọc được), `agent.sock` (macOS), `blacklist.db` + `blacklist.fp` (danh sách đen), `sources/` + `blacklist_update.json` (bản sao từng nguồn, ETag, lịch tự cập nhật), `rdap_bootstrap.json` (bảng máy chủ RDAP của IANA), `cache.db` (cache tuổi tên miền),
`decisions.db` (nhật ký) và `chotto.log`.

- Khi **Tầng 3 bật**, chỉ **tên miền** (không kèm đường dẫn) được gửi tới máy chủ RDAP của nhà đăng ký (theo bảng IANA, dự phòng `rdap.org`) và máy chủ WHOIS. Khi **tắt**, CHOTTO không gửi tên miền nào ra ngoài.
- Agent tự tải danh sách đen mỗi ngày (chỉ tải xuống, không gửi gì về link bạn bấm). Tắt bằng `"auto_update": false` trong `config.json`.
- Nhật ký chỉ lưu **tên miền đăng ký** (không đường dẫn, không query như mã OTP), điểm, mã tín hiệu, quyết định và thời gian cân nhắc; tự xóa sau 90 ngày; tắt được trong cài đặt.

## Xử lý sự cố
- **Bấm link không thấy CHOTTO phản ứng**: chạy `python main.py agent-status` và `python main.py log`. Nếu báo “chưa có dòng nào” nghĩa là CHOTTO chưa từng được gọi, hãy kiểm tra lại bước đặt trình duyệt mặc định.
- **Muốn xem giao diện cảnh báo mà link không từ Zalo**: dùng `--force`.
- **`ModuleNotFoundError: tkinter`** (Linux): cài `python3-tk`.
- **py2app báo “Multiple top-level packages”**: bạn đang chạy lệnh sai thư mục, hãy chạy từ thư mục gốc dự án.
- **Muốn tắt agent nền**: đặt `"agent_enabled": false` trong `config.json` rồi chạy `main.py agent-stop`.
- **Đổi trình duyệt mặc định sau khi đã cài CHOTTO**: chạy lại `main.py install` để CHOTTO ghi nhớ trình duyệt mới.
- **Pylance báo `Import "setuptools" could not be resolved`**: `pip install -r requirements.txt` trong đúng môi trường VS Code đang chọn.

## Hạn chế đã biết
- **Chưa kiểm thử trên máy thật** các phần: giao diện Tkinter, ghi registry, gọi WinAPI nhận diện Zalo, khởi chạy trình duyệt thật, `::tk::mac::LaunchURL`. Phần logic thuần của chúng (tách lệnh registry, dựng argv, quyết định nguồn gọi, luồng xử lý link) đã có test; phần gọi hệ điều hành cần thử tay.
- **Launcher vẫn là một tiến trình Python**: thời gian khởi động trình thông dịch (~0,1 giây trên máy thử Linux, có thể lâu hơn trên Windows) cộng ~10 ms giao link. Mục tiêu dưới 100 ms của lộ trình cần launcher viết bằng ngôn ngữ biên dịch; để sau.
- **Agent chưa chạy** (vừa cài, bị tắt, hoặc `agent_enabled = false` trong `config.json`): launcher tự xử lý link như bản 1.0 và khởi động agent cho lần sau. Agent khác phiên bản launcher (vừa cập nhật) sẽ tự tắt.
- **Cấu trúc gói**: mới tách phần dịch vụ ra `chotto/service/`; việc dời các module còn lại vào `detect/`, `platform/`, `storage/` như lộ trình chỉ là đổi chỗ file, chưa làm để tránh xáo trộn.
- **Nhận diện Zalo trên macOS có thể sai/trễ**: dựa vào ứng dụng đang ở foreground lúc CHOTTO khởi động. Link không xác định được vẫn được kiểm tra (`unknown_caller_policy = "inspect"`) và chỉ cảnh báo khi đáng ngờ; đặt `"forward"` trong `config.json` để mở thẳng.
- **Nguồn danh sách đen** (ChongLuaDao, Phishing.Database, PhishTank) lấy từ tài liệu công khai và có thể đổi định dạng hoặc địa chỉ; parser nhận JSON/text/CSV. PhishTank thường cần API key (thêm vào URL trong `rules.json`).
- **Tầng 3** chạy song song RDAP và WHOIS (cổng 43) với hạn chót tuyệt đối 1,8 giây, chưa có DNS SOA. Tên miền `.vn` chưa có RDAP (VNNIC không có trong bảng IANA) nên chỉ trông vào WHOIS; tra không được thì quay về điểm Tầng 2. Chưa dùng Certificate Transparency làm nguồn dự phòng vì một lượt tra crt.sh thường vượt quá 1,8 giây.
- **“Hash Set”** của đề án được hiện thực bằng mảng dấu vân tay 64-bit đã sắp xếp trong RAM (~8 byte/mục, tìm nhị phân). Xác suất một tên miền sạch trùng dấu vân tay là n/2⁶⁴ (≈ 2·10⁻¹⁴ với 400.000 mục), nên không cần SQLite để xác nhận lại.
- **Danh sách tên miền phổ biến** lấy từ CrUX (lượt truy cập thật của người dùng Chrome), không phải danh sách “an toàn”: trang phổ biến vẫn có thể bị chiếm quyền, nên Tầng 1 vẫn áp dụng. 10 tên miền .vn từng có host nằm trong Phishing.Database (nền tảng cho người dùng tự tạo trang như `pancake.vn`, `zing.vn`) bị loại khỏi danh sách.
- **Trọng số Tầng 2**: 6 dấu hiệu từ vựng phổ biến (http, hosting miễn phí, gạch ngang, TLD, entropy, chữ số) được hiệu chỉnh bằng hồi quy logistic; các dấu hiệu hiếm (mạo danh thương hiệu, đồng hình, @, IP...) giữ trọng số viết tay vì không đủ dữ liệu để học.
- **Báo nhầm với trang hợp pháp chứa tên thương hiệu** nhưng chưa có trong danh sách (ví dụ đại lý `dangky5gviettel.com.vn`) vẫn khoảng 1,25%. Thêm tên miền chính thức vào `brands[].domains` trong `rules.json` để sửa từng trường hợp.
- **Danh sách tên miền mới đăng ký (NRD)** chưa có: chưa tìm được nguồn có giấy phép rõ ràng tải được tự động.
- **AI's Advices** hiện là bộ tư vấn dựa trên luật, không phải mô hình ngôn ngữ. Giữ nguyên chữ ký `advise(result) -> str` thì có thể thay bằng LLM chạy local (Ollama...) sau này.
- **Báo nhầm** ở vùng xám vẫn có thể xảy ra (ví dụ tên miền hợp pháp chứa từ “momo”); Tầng 3 giúp giảm nhưng không loại bỏ.
## Giấy phép dữ liệu đi kèm
- `chotto/data/public_suffix_list.dat`: Public Suffix List, Mozilla Public License 2.0 (https://publicsuffix.org). Cập nhật bằng cách thay file này bằng bản mới từ publicsuffix.org.
- `chotto/data/confusables_ascii.json`: rút gọn từ Unicode TR39 `confusables.txt`, theo Unicode License v3.
- `chotto/data/popular_vn.txt`: sinh từ Chrome UX Report (Google, CC BY 4.0) qua https://github.com/zakird/crux-top-lists. Sinh lại bằng `tools/build_popular.py`.
