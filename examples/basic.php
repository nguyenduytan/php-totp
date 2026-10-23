<?php
/**
 * Ví dụ cơ bản — chạy: php examples/basic.php
 */

require __DIR__ . '/../GoogleAuthenticator.php';

$ga = new GoogleAuthenticator();

// 1. Tạo secret cho user
$secret = $ga->generateSecretKey();          // 32 ký tự Base32

// 2. Lưu $secret vào DB gắn với user_id
//    (KHÔNG bao giờ log hoặc echo secret trong production)

// 3. Hiển thị QR cho user quét
echo "=== QR setup ===\n";
echo $ga->renderQRCodeImg('user@example.com', $secret, 'MyApp') . "\n\n";

// 4. Khi user nhập mã 6 số để xác nhận setup
echo "=== Verify setup ===\n";
echo "Nhập mã từ app: ";
$input = trim(fgets(STDIN));

if ($ga->verifyCode($secret, $input)) {
    echo "✅ Setup thành công. Bật 2FA cho user.\n";
} else {
    echo "❌ Mã sai hoặc hết hạn.\n";
    exit(1);
}

// 5. Sinh recovery codes dự phòng
echo "\n=== Recovery codes (cho user tải về) ===\n";
foreach ($ga->generateRecoveryCodes(8) as $code) {
    echo "  $code\n";
}
