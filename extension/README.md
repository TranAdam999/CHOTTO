# CHOTTO cho Zalo Web – tiện ích trình duyệt (v1.4.0)

Tiện ích Manifest V3 cho **Chrome, Edge** (≥ 111) và **Firefox** (≥ 128). Khi bạn bấm một liên kết trên
`chat.zalo.me`, CHOTTO thẩm định nó **ngay trong trình duyệt** bằng đúng engine 3 tầng của bản Desktop.
Liên kết an toàn được mở như bình thường. Liên kết đáng ngờ hiện màn hình **“Khoan đã!”** với nút “vẫn mở”
bị khóa vài giây.

## Cài đặt

### Chrome / Edge (chế độ nhà phát triển)
1. Giải nén `chotto-extension-chrome-1.4.0.zip`, hoặc dùng thẳng thư mục `extension/` này.
2. Mở `chrome://extensions` (Edge: `edge://extensions`) và bật **Developer mode**.
3. Bấm **Load unpacked** rồi chọn thư mục vừa giải nén.
4. Trang cài đặt của CHOTTO tự mở. Sau đó mở hoặc tải lại `chat.zalo.me`.

### Firefox
1. Mở `about:debugging#/runtime/this-firefox`, bấm **Load Temporary Add-on…** rồi chọn file
   `chotto-extension-firefox-1.4.0.zip`. Muốn cài vĩnh viễn thì gói phải được Mozilla ký.
2. Firefox coi quyền truy cập trang web là quyền tùy chọn. Vào `about:addons` → CHOTTO → **Permissions**
   và bật quyền cho `chat.zalo.me`, `rdap.org`, `data.iana.org` và các nguồn danh sách đen.

## Cách hoạt động
| Thành phần | Vai trò |
|---|---|
| `src/content.js` (isolated world, `document_start`, mọi frame) | Chặn ở pha capture trên `window`, trước mọi handler của Zalo: click trái (cả Ctrl/⌘/Shift), chuột giữa (`auxclick`), Enter trên liên kết. Liên kết nội bộ của Zalo và scheme khác http(s) không bị đụng tới. |
| `src/main_world.js` (`world: "MAIN"`) | Bọc `window.open` của trang. Liên kết ra ngoài được chuyển cho content script qua sự kiện `chotto:open`. Lời gọi không đi kèm thao tác thật của người dùng (trong 2 giây) bị bỏ qua. |
| `src/background.js` (service worker) | Chạy engine, mở tab cho liên kết an toàn và cấp **vé dùng một lần** cho liên kết rủi ro. Nút “vẫn mở” chỉ có hiệu lực khi vé đúng tab, chưa hết hạn và đã qua thời gian khóa. Nếu không có vé, service worker không mở gì, dù giao diện có bị vượt mặt. |
| Lưới an toàn (`webNavigation`) | Tab mới sinh từ tab Zalo mà chưa qua kiểm tra (menu chuột phải “Mở trong tab mới”, form `target=_blank`, `window.open("")` rồi điều hướng…) bị chuyển sang `src/ui/warn.html` để thẩm định và hiện cùng màn hình. |
| `src/ui/friction.js` | Hộp thoại nằm trong **Shadow DOM `closed`** và `<dialog>` modal ở top layer, nên script của trang không đọc, sửa hay bấm hộ được. Nút “vẫn mở” không nhận phím. Nó chỉ nhận cú bấm chuột/chạm thật (`isTrusted`, `detail > 0`) mà lúc nhấn xuống đã hết thời gian khóa. |
| `src/engine/` | Engine 3 tầng chuyển từ `chotto/*.py`, dùng chung `rules.json`. |

Thời gian khóa nút “vẫn mở” mặc định là 5 giây ở mức Đáng ngờ. Mức Rất nguy hiểm cộng 3 giây, Danh sách đen
cộng 5 giây, giống bản Desktop.

### Ba tầng trong trình duyệt
- **Tầng 1 – danh sách đen.** Danh sách là mảng dấu vân tay 64-bit đã sắp xếp (SHA-256 của WebCrypto, lấy
  8 byte), lưu trong IndexedDB và tra bằng tìm nhị phân trong RAM. Danh sách tự cập nhật mỗi ngày từ các
  nguồn trong `rules.json`, dùng ETag/Last-Modified, với các quy tắc an toàn của bản Desktop:
  - nguồn lỗi thì dùng lại bản sao gần nhất;
  - danh sách mới co rút bất thường thì bị từ chối;
  - mục là hậu tố công cộng hoặc trùng tên miền chính thức thì bị loại.
- **Tầng 2 – heuristics tiếng Việt.** Cài lại 1-1 bằng JavaScript. Bộ phân tích URL là chính `new URL()`
  của trình duyệt (WHATWG), nên tiện ích nhìn URL đúng như trang sẽ mở.
- **Tầng 3 – tuổi tên miền qua RDAP.**
  - Hỏi máy chủ nhà đăng ký theo bảng IANA bootstrap. Lỗi mạng/CORS thì thử lại qua `rdap.org`.
  - Hạn chót tổng là 1,8 giây (dùng `AbortController`). Kết quả được cache 48 giờ, thất bại được nhớ 1 giờ.
  - Trình duyệt không mở được cổng 43, nên tiện ích **không có WHOIS**. Vì vậy với `.vn` (chưa có RDAP),
    Tầng 3 không tra được và CHOTTO quay về điểm Tầng 2 kèm lời khuyên cục bộ.

## Quyền riêng tư
- Không có URL nào được gửi tới máy chủ của CHOTTO, vì CHOTTO không có máy chủ.
- Tầng 3 (tắt được) chỉ gửi **tên miền đăng ký** tới dịch vụ RDAP công khai.
- Nhật ký quyết định (tắt được, mặc định giữ 90 ngày) chỉ lưu tên miền đăng ký, mức, điểm, lựa chọn và
  thời điểm. Nó không lưu đường dẫn, URL đầy đủ hay nội dung tin nhắn.

## Phát triển
```
cd extension
npm install                       # chỉ công cụ phát triển: fake-indexeddb, playwright, typescript, @types
npm test                          # 16 test Node: engine, IndexedDB, cập nhật, khớp 2.521 URL với bản Python
npm run typecheck                 # tsc kiểm tra kiểu JSDoc (// @ts-check) toàn bộ mã
npm run e2e                       # 8 test end-to-end với Chromium thật và trang chat.zalo.me giả lập
node e2e/screenshots.mjs out/     # chụp ảnh minh họa trải nghiệm

cd ..
python tools/sync_extension_data.py            # sau khi sửa chotto/data hoặc chotto/advisor.py
python tools/gen_engine_vectors.py --phish ... --crux ...   # sinh lại bộ URL dùng chung khi đổi luật
python tools/build_extension.py                # dist/chotto-extension-{chrome,firefox}-1.4.0.zip
```
**Quy tắc khi đổi luật:** sửa `chotto/data/rules.json`, rồi chạy `sync_extension_data.py` và
`gen_engine_vectors.py`. Sau đó cả `python -m unittest` lẫn `npm test` phải xanh. `tests/test_parity.py`
sẽ báo lỗi nếu quên đồng bộ.

## Hạn chế đã biết
- **Chưa thử trên chat.zalo.me thật.** E2E chạy trên trang giả lập có thẻ `<a target=_blank>`, handler kiểu
  React, `window.open` và form. Nếu Zalo Web mở link theo cách khác, lưới an toàn tab mới vẫn bắt được,
  nhưng trang đích có thể đã bắt đầu tải trước khi bị chuyển hướng.
- **Chưa thử trên Firefox thật.** Gói Firefox được sinh tự động, nhưng mới chỉ được kiểm tra trên Chromium.
- Kéo-thả liên kết sang thanh tab không đi qua Zalo nên không bị kiểm tra.
- Thiếu WHOIS như đã nói ở trên. Các nguồn danh sách đen (ChongLuaDao, PhishTank) có thể đòi API key hoặc
  đổi định dạng. Khi đó trang cài đặt hiện lỗi của từng nguồn và CHOTTO giữ nguyên danh sách hiện có.
- Lần đầu cài, danh sách đen chỉ có vài mục khởi tạo cho tới khi cập nhật xong (khoảng 1 phút sau khi
  cài, hoặc bấm “Cập nhật ngay”).
