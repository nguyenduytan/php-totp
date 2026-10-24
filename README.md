# PHP TOTP — Google Authenticator

[![PHP Version](https://img.shields.io/badge/php-%3E%3D7.1-777bb4?logo=php&logoColor=white)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![RFC 6238](https://img.shields.io/badge/RFC-6238-blue.svg)](https://datatracker.ietf.org/doc/html/rfc6238)
[![Latest Version](https://img.shields.io/packagist/v/nguyenduytan/php-totp.svg)](https://packagist.org/packages/nguyenduytan/php-totp)
[![Total Downloads](https://img.shields.io/packagist/dt/nguyenduytan/php-totp.svg)](https://packagist.org/packages/nguyenduytan/php-totp)

> Thư viện TOTP siêu nhẹ, **chỉ 1 file PHP duy nhất**, không dependency.  
> Tương thích hoàn toàn với Google Authenticator, Authy, Microsoft Authenticator, 1Password, Bitwarden.

**Author:** [Tony Nguyễn](https://nguyenduytan.com) · **License:** MIT · **Version:** 2.1.0

---

## Vì sao chọn thư viện này?

- 🪶 **1 file duy nhất** — copy vào project, `require`, xong. Không Composer, không autoloader, không extension.
- ✅ **Chuẩn RFC 6238** — verify được với mọi authenticator app phổ biến.
- 🔐 **An toàn** — so sánh hằng thời gian, chặn mã rác, Base32 decode chặt.
- 🛡️ **Replay protection** — trả về `time-slice` đã khớp để tầng app tự chặn dùng lại mã.
- 🖼️ **QR không bao giờ chết** — 4 nguồn dự phòng + fallback phía client.
- 🧰 **Recovery codes** — sinh bộ mã backup sẵn dùng.
- 🧪 **CI test** trên PHP 7.4 → 8.3.

---

## Yêu cầu

- PHP **7.1+** (khuyến nghị 8.0+)
- Extension: không bắt buộc. Nếu có `curl` → bật được probe QR server-side.

---

## Cài đặt

### Cách 1 — Copy file (không cần Composer)

Tải `GoogleAuthenticator.php` về, đặt vào project, rồi:

```php
require 'path/to/GoogleAuthenticator.php';
$ga = new GoogleAuthenticator();
```

### Cách 2 — Composer

```bash
composer require nguyenduytan/php-totp
```

```php
require 'vendor/autoload.php';
$ga = new \GoogleAuthenticator();
```

---

## Bắt đầu nhanh

```php
<?php
require 'GoogleAuthenticator.php';

$ga = new GoogleAuthenticator();

// 1. Sinh secret cho user (LƯU vào DB, KHÔNG log)
$secret = $ga->generateSecretKey(); // 32 ký tự Base32 ≈ 160-bit

// 2. Hiển thị QR cho user quét
echo $ga->renderQRCodeImg('user@example.com', $secret, 'MyApp');

// 3. Xác thực mã user nhập
if ($ga->verifyCode($secret, $_POST['otp'])) {
    // login OK
} else {
    // sai mã
}
```

---

## API

### Secret

| Method | Mô tả |
|---|---|
| `generateSecretKey(int $length = 32): string` | Secret Base32 ngẫu nhiên (16–128 ký tự). |
| `isValidSecret(string $secret): bool` | Kiểm tra secret hợp lệ & đủ mạnh (≥ 80-bit). |
| `normalizeSecret(string $secret): string` | Làm sạch input (viết hoa, bỏ `=`, space, `-`). |

### Verify

| Method | Mô tả |
|---|---|
| `verifyCode(string $secret, string $code, int $discrepancy = 1): bool` | Xác thực mã 6 số, cho phép ±1 block 30s. |
| `verifyCodeAndGetTimeSlice(...): int\|false` | Như trên, trả thêm time-slice đã khớp (dùng cho replay protection). |
| `getTimeSlice(?int $timestamp = null): int` | Time-slice hiện tại (= `floor(time()/30)`). |
| `getTimeRemaining(): int` | Số giây còn lại của block hiện tại (UI đếm ngược). |
| `getCodeAt(string $secret, ?int $timestamp = null): string` | Sinh mã tại thời điểm (chỉ dùng cho **test**). |

### QR

| Method | Mô tả |
|---|---|
| `getProvisioningUri(string $name, string $secret, string $issuer): string` | URI `otpauth://` chuẩn Google. |
| `getQRCodeUrls(...): string[]` | Danh sách 4 URL QR dự phòng. |
| `getQRCodeUrl(..., bool $verify = false): string` | 1 URL. `$verify = true` → dò server-side. |
| `renderQRCodeImg(...): string` | Thẻ `<img>` có `onerror` tự chuyển nguồn. |

### Recovery

| Method | Mô tả |
|---|---|
| `generateRecoveryCodes(int $count = 8, int $length = 10): string[]` | Bộ mã backup dạng `XXXX-XXXXX`. |

---

## Replay protection (khuyến nghị cho production)

TOTP thuần cho phép **dùng lại mã trong cùng block 30s**. Bản này cung cấp `verifyCodeAndGetTimeSlice()` để bạn tự chặn:

```php
$ga = new GoogleAuthenticator();
$slice = $ga->verifyCodeAndGetTimeSlice($secret, $_POST['otp']);

if ($slice !== false) {
    $key = "otp_used:{$userId}:{$slice}";
    if ($redis->set($key, 1, ['nx', 'ex' => 60])) {
        // ✅ Lần đầu dùng mã này → cho login
    } else {
        // ❌ Mã đã dùng → từ chối
    }
} else {
    // ❌ Sai mã
}
```

---

## Bảo mật — checklist

Thư viện chỉ lo phần **tính và so khớp mã**. Tầng ứng dụng **phải** tự lo:

- ✅ **Rate limit** — 5 lần/phút/IP/user (Redis hoặc middleware).
- ✅ **Replay protection** — dùng `verifyCodeAndGetTimeSlice()` + Redis/DB (xem trên).
- ✅ **Khoá account** — sau N lần sai liên tiếp (5–10).
- ✅ **Không log** secret và mã OTP (kể cả khi debug).
- ✅ **TLS** — 2FA không thay thế được HTTPS.
- ✅ **Encrypt secret at rest** — mã hoá cột `totp_secret` trong DB (AES-GCM).

---

## Testing

```bash
php -l GoogleAuthenticator.php
php examples/basic.php
```

CI tự chạy trên PHP 7.4 / 8.0 / 8.1 / 8.2 / 8.3 khi push.

---

## Changelog

Xem [CHANGELOG.md](CHANGELOG.md).

---

## License

[MIT](LICENSE) © 2025 [Tony Nguyễn](https://nguyenduytan.com)

---

## Liên hệ

- 🌐 Website: [https://nguyenduytan.com](https://nguyenduytan.com)
- 🐛 Bug / feature request: [mở issue](https://github.com/nguyenduytan/php-totp/issues)
