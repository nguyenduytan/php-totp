<?php
/**
 * =====================================================================
 *  GoogleAuthenticator — TOTP RFC 6238 (tương thích Google Authenticator)
 * =====================================================================
 *
 *  Single-file, không phụ thuộc thư viện ngoài. Yêu cầu PHP >= 7.1.
 *
 *  @author     Tony Nguyễn
 *  @website    https://nguyenduytan.com
 *  @copyright  2025 Tony Nguyễn
 *  @license    MIT — https://opensource.org/licenses/MIT
 *  @version    2.1.0
 *  @package    GoogleAuthenticator
 *
 * ---------------------------------------------------------------------
 *  Tính năng
 * ---------------------------------------------------------------------
 *   - TOTP RFC 6238 — tương thích Google Auth / Authy / Microsoft Auth.
 *   - Base32 decode chặt chẽ, báo lỗi thay vì âm thầm trả key sai.
 *   - Verify hằng thời gian (hash_equals) + chặn mã rác (regex 6 số).
 *   - verifyCodeAndGetTimeSlice() → trả về time-slice đã khớp để
 *     tầng ứng dụng tự cài đặt replay protection (Redis/DB).
 *   - isValidSecret() + normalizeSecret() để kiểm tra & làm sạch input.
 *   - generateRecoveryCodes() cho backup 2FA.
 *   - getQRCodeUrls() trả 4 nguồn QR dự phòng; renderQRCodeImg()
 *     tự động chuyển nguồn phía client khi ảnh lỗi (onerror chain).
 *   - getProvisioningUri() đúng spec Google Key Uri Format.
 *   - Tự chứa (self-contained), không cần Composer, không cần extension.
 *
 * ---------------------------------------------------------------------
 *  Giấy phép
 * ---------------------------------------------------------------------
 *  MIT License — Copyright (c) 2025 Tony Nguyễn
 *  Xem https://nguyenduytan.com hoặc file LICENSE kèm theo.
 *  Bạn được tự do dùng, sửa, phân phối, miễn giữ nguyên header này.
 * =====================================================================
 */

class GoogleAuthenticator
{
    /** Phiên bản thư viện (dùng cho debug / hiển thị). */
    public const VERSION = '2.1.0';

    /** Tác giả. */
    public const AUTHOR  = 'Tony Nguyễn';

    /** Website tác giả. */
    public const WEBSITE = 'https://nguyenduytan.com';

    /** Bảng ký tự Base32 (RFC 4648). */
    private const BASE32_MAP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Số chữ số OTP. */
    private const DIGITS = 6;

    /** Chu kỳ (giây). */
    private const PERIOD = 30;

    /** Giới hạn cửa sổ sai lệch cho phép (± block). */
    private const MAX_DISCREPANCY = 10;

    /** Bảng ký tự recovery code (bỏ I/O/0/1 dễ nhầm). */
    private const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    /** @var array<string,bool> cache sống/chết URL QR trong 1 request. */
    private static $qrAliveCache = [];

    /** @var string|null URL QR đang hoạt động (cache). */
    private static $qrWorkingUrl = null;

    /* =================================================================
     *  SECRET KEY
     * ================================================================= */

    /**
     * Tạo Secret Key ngẫu nhiên dạng Base32.
     * Mặc định 32 ký tự (~160-bit) theo khuyến nghị RFC 6238.
     *
     * @param int $length Số ký tự (16..128). Tối thiểu 16 (≈80-bit).
     */
    public function generateSecretKey($length = 32)
    {
        $length = (int) $length;
        if ($length < 16)  $length = 16;
        if ($length > 128) $length = 128;

        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= self::BASE32_MAP[$this->randomInt(0, 31)];
        }
        return $secret;
    }

    /**
     * Chuẩn hoá secret từ input người dùng (viết hoa, bỏ padding/khoảng trắng).
     */
    public function normalizeSecret($secret)
    {
        $secret = strtoupper(trim((string) $secret));
        return str_replace(['=', ' ', "\t", "\r", "\n", '-'], '', $secret);
    }

    /**
     * Kiểm tra secret có phải Base32 hợp lệ và đủ mạnh.
     * @return bool true nếu decode được và >= 80 bit.
     */
    public function isValidSecret($secret)
    {
        try {
            $raw = $this->base32Decode($secret);
            return strlen($raw) >= 10; // >= 80 bit — ngưỡng tối thiểu thực tế
        } catch (Throwable $e) {
            return false;
        }
    }

    /* =================================================================
     *  TIME SLICE / RECOVERY CODES
     * ================================================================= */

    /**
     * Time-slice hiện tại (hoặc tại $timestamp bất kỳ).
     * Public để tầng ứng dụng lưu DB chống replay.
     */
    public function getTimeSlice($timestamp = null)
    {
        $t = ($timestamp === null) ? time() : (int) $timestamp;
        return (int) floor($t / self::PERIOD);
    }

    /** Số giây còn lại của block hiện tại (UI đếm ngược). */
    public function getTimeRemaining()
    {
        return self::PERIOD - (time() % self::PERIOD);
    }

    /**
     * Tạo bộ recovery codes (backup 2FA).
     * Không phụ thuộc secret, chỉ là chuỗi ngẫu nhiên dạng "XXXX-XXXXX".
     *
     * @return string[]
     */
    public function generateRecoveryCodes($count = 8, $length = 10)
    {
        $count  = max(1, min(20, (int) $count));
        $length = max(8, min(16, (int) $length));
        if ($length % 2 !== 0) $length++; // chia đôi đều để chèn dấu '-'

        $max   = strlen(self::RECOVERY_ALPHABET) - 1;
        $codes = [];

        for ($c = 0; $c < $count; $c++) {
            $raw = '';
            for ($i = 0; $i < $length; $i++) {
                $raw .= self::RECOVERY_ALPHABET[$this->randomInt(0, $max)];
            }
            $half    = intdiv($length, 2);
            $codes[] = substr($raw, 0, $half) . '-' . substr($raw, $half);
        }
        return $codes;
    }

    /* =================================================================
     *  VERIFY / CODE
     * ================================================================= */

    /**
     * Xác thực mã OTP.
     *
     * @param string $secret      Secret Base32.
     * @param string $code        Mã 6 chữ số người dùng nhập.
     * @param int    $discrepancy Số block 30s cho phép lệch mỗi bên.
     */
    public function verifyCode($secret, $code, $discrepancy = 1)
    {
        return $this->verifyCodeAndGetTimeSlice($secret, $code, $discrepancy) !== false;
    }

    /**
     * Như verifyCode() nhưng trả về time-slice đã khớp (int) hoặc false.
     * Dùng cho replay protection:
     *   $slice = $ga->verifyCodeAndGetTimeSlice($secret, $code);
     *   if ($slice !== false && !$store->hasUsed($userId, $slice)) {
     *       $store->markUsed($userId, $slice, 60); // TTL > 30s
     *       // ... login OK
     *   }
     *
     * @return int|false
     */
    public function verifyCodeAndGetTimeSlice($secret, $code, $discrepancy = 1)
    {
        $code = trim((string) $code);
        if (!preg_match('/^[0-9]{6}$/', $code)) {
            return false;
        }

        $discrepancy = (int) $discrepancy;
        if ($discrepancy < 0) $discrepancy = 0;
        if ($discrepancy > self::MAX_DISCREPANCY) $discrepancy = self::MAX_DISCREPANCY;

        try {
            // Decode secret 1 lần cho cả vòng lặp (tối ưu so với bản cũ).
            $rawKey = $this->base32Decode($secret);
        } catch (Throwable $e) {
            return false;
        }

        $slice        = $this->getTimeSlice();
        $matchedSlice = null;

        // Số lần hash_equals luôn cố định = 2*discrepancy+1
        // → không rò rỉ timing theo vị trí khớp.
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calc = $this->hotp($rawKey, $slice + $i);
            if (hash_equals($calc, $code)) {
                $matchedSlice = $slice + $i;
            }
        }

        return $matchedSlice === null ? false : $matchedSlice;
    }

    /**
     * Sinh mã OTP tại một thời điểm — CHỈ DÙNG CHO UNIT TEST.
     * Không expose ra production.
     */
    public function getCodeAt($secret, $timestamp = null)
    {
        $rawKey = $this->base32Decode($secret);
        return $this->hotp($rawKey, $this->getTimeSlice($timestamp));
    }

    /** HOTP trên raw key + counter. */
    private function hotp($rawKey, $counter)
    {
        $time = pack('N*', 0) . pack('N*', $counter & 0xFFFFFFFF);
        $hmac = hash_hmac('SHA1', $time, $rawKey, true);

        $offset = ord($hmac[19]) & 0x0F;
        $value  = ((ord($hmac[$offset])     & 0x7F) << 24)
                | ((ord($hmac[$offset + 1]) & 0xFF) << 16)
                | ((ord($hmac[$offset + 2]) & 0xFF) << 8)
                |  (ord($hmac[$offset + 3]) & 0xFF);

        return str_pad((string) ($value % 1000000), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /* =================================================================
     *  BASE32
     * ================================================================= */

    /**
     * Giải mã Base32. Ném InvalidArgumentException nếu không hợp lệ.
     */
    public function base32Decode($b32)
    {
        $b32 = $this->normalizeSecret($b32);

        if ($b32 === '') {
            throw new InvalidArgumentException('Secret key rỗng.');
        }

        $bits = '';
        $len  = strlen($b32);
        for ($i = 0; $i < $len; $i++) {
            $pos = strpos(self::BASE32_MAP, $b32[$i]);
            if ($pos === false) {
                throw new InvalidArgumentException(
                    'Secret key chứa ký tự không hợp lệ (Base32).'
                );
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $out   = '';
        $bytes = intdiv(strlen($bits), 8);
        for ($i = 0; $i < $bytes; $i++) {
            $out .= chr(bindec(substr($bits, $i * 8, 8)));
        }
        return $out;
    }

    /* =================================================================
     *  QR CODE — 4 nguồn dự phòng
     * ================================================================= */

    /** Tạo otpauth:// URI chuẩn theo Key Uri Format của Google. */
    public function getProvisioningUri($name, $secret, $issuer = 'getStocks')
    {
        $issuer = str_replace(':', '', trim((string) $issuer));
        if ($issuer === '') $issuer = 'Authenticator';

        $name = trim((string) $name);
        if ($name === '') $name = 'user';

        $label = rawurlencode($issuer) . ':' . rawurlencode($name);
        $query = http_build_query([
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::DIGITS,
            'period'    => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);

        return 'otpauth://totp/' . $label . '?' . $query;
    }

    /**
     * Danh sách URL QR (nguồn chính + dự phòng) theo thứ tự ưu tiên.
     * @return string[]
     */
    public function getQRCodeUrls($name, $secret, $issuer = 'getStocks', $size = 400)
    {
        $size = max(100, min(1000, (int) $size));
        $data = rawurlencode($this->getProvisioningUri($name, $secret, $issuer));

        return [
            // 1) Nguồn chính: vietqr.cc
            'https://vietqr.cc/api/qr?s=' . $size
                . '&m=0&color=%23b42318&bg=%23fff7ed&shape=rounded&frame=corners&data=' . $data,

            // 2) goqr.me
            'https://api.qrserver.com/v1/create-qr-code/?size=' . $size . 'x' . $size
                . '&margin=0&data=' . $data,

            // 3) QuickChart
            'https://quickchart.io/qr?size=' . $size . '&margin=0&text=' . $data,

            // 4) Google Chart API (legacy)
            'https://chart.googleapis.com/chart?chs=' . $size . 'x' . $size
                . '&cht=qr&chl=' . $data . '&choe=UTF-8',
        ];
    }

    /**
     * Trả về 1 URL QR.
     *
     * @param bool $verify Nếu true: dò server-side (cURL/stream, timeout 1.5s)
     *                     để chọn nguồn đang sống. Chỉ nên bật ở trang setup.
     */
    public function getQRCodeUrl($name, $secret, $issuer = 'getStocks', $size = 400, $verify = false)
    {
        $urls = $this->getQRCodeUrls($name, $secret, $issuer, $size);

        if (!$verify) return $urls[0];
        if (self::$qrWorkingUrl !== null) return self::$qrWorkingUrl;

        foreach ($urls as $url) {
            if ($this->isUrlAlive($url)) {
                self::$qrWorkingUrl = $url;
                return $url;
            }
        }
        return $urls[0];
    }

    /**
     * Render <img> QR kèm cơ chế tự đổi nguồn khi ảnh lỗi (client-side).
     * Ví dụ: echo $ga->renderQRCodeImg('user@x', $secret);
     */
    public function renderQRCodeImg($name, $secret, $issuer = 'getStocks', $size = 200, $alt = 'Mã QR')
    {
        $size = max(100, min(1000, (int) $size));
        $urls = $this->getQRCodeUrls($name, $secret, $issuer, $size);

        $primary = array_shift($urls);
        $rest    = json_encode(
            array_values($urls),
            JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP
            | JSON_HEX_APOS | JSON_HEX_QUOT
        );
        if ($rest === false) $rest = '[]';

        $onerror = "var q=this,f=[];try{f=JSON.parse(q.getAttribute('data-srcs')||'[]')}catch(e){}"
                 . "if(f.length){q.src=f.shift();q.setAttribute('data-srcs',JSON.stringify(f))}"
                 . "else{q.onerror=null}";

        return '<img src="' . htmlspecialchars($primary, ENT_QUOTES, 'UTF-8') . '"'
             . ' width="' . $size . '" height="' . $size . '"'
             . ' alt="' . htmlspecialchars($alt, ENT_QUOTES, 'UTF-8') . '"'
             . ' data-srcs="' . htmlspecialchars($rest, ENT_QUOTES, 'UTF-8') . '"'
             . ' onerror="' . htmlspecialchars($onerror, ENT_QUOTES, 'UTF-8') . '">';
    }

    /* =================================================================
     *  INTERNALS
     * ================================================================= */

    /** random_int có fallback cho môi trường hiếm. */
    private function randomInt($min, $max)
    {
        if (function_exists('random_int')) {
            return random_int($min, $max);
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes(4, $strong);
            if ($bytes !== false && strlen($bytes) === 4) {
                $n = unpack('N', $bytes);
                $n = $n[1] & 0x7FFFFFFF;
                return $min + ($n % ($max - $min + 1));
            }
        }
        return mt_rand($min, $max);
    }

    private function isUrlAlive($url, $timeoutMs = 1500)
    {
        if (isset(self::$qrAliveCache[$url])) {
            return self::$qrAliveCache[$url];
        }
        $alive = $this->probeUrl($url, $timeoutMs);
        self::$qrAliveCache[$url] = $alive;
        return $alive;
    }

    private function probeUrl($url, $timeoutMs)
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_NOBODY            => true,
                CURLOPT_RETURNTRANSFER    => true,
                CURLOPT_FOLLOWLOCATION    => true,
                CURLOPT_MAXREDIRS         => 3,
                CURLOPT_CONNECTTIMEOUT_MS => $timeoutMs,
                CURLOPT_TIMEOUT_MS        => $timeoutMs,
                CURLOPT_SSL_VERIFYPEER    => true,
                CURLOPT_USERAGENT         => 'GoogleAuthenticator/' . self::VERSION,
            ]);
            curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            return $this->isHttpOk($code);
        }

        if (ini_get('allow_url_fopen')) {
            $ctx = stream_context_create([
                'http'  => ['method' => 'HEAD', 'timeout' => $timeoutMs / 1000, 'ignore_errors' => true],
                'https' => ['method' => 'HEAD', 'timeout' => $timeoutMs / 1000, 'ignore_errors' => true],
            ]);
            $headers = @get_headers($url, true, $ctx);
            if (is_array($headers) && isset($headers[0])
                && preg_match('/\s(\d{3})\b/', $headers[0], $m)) {
                return $this->isHttpOk((int) $m[1]);
            }
        }

        return true; // không probe được → coi như OK để không chặn UI
    }

    private function isHttpOk($code)
    {
        return ($code >= 200 && $code < 400) || $code === 405;
    }
}
