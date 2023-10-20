<?php
class Crypto {
    const AES_IV = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    public static function decode_auth($auth) {
        $result_list = [];
        $digits = '0123456789';

        $translation_table_lower = strtr(
            'abcdefghijklmnopqrstuvwxyz',
            'abcdefghijklmnopqrstuvwxyz',
            'mlkjihgfedcbaqrstuvwxyz'
        );

        $translation_table_upper = strtr(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'tsrqpnomlkihgfedcbaZXWVUTSRQPONMLKIHGFEDCBA'
        );

        for ($i = 0; $i < strlen($auth); $i++) {
            $char = $auth[$i];
            if (strpos('abcdefghijklmnopqrstuvwxyz', $char) !== false) {
                $result_list[] = $translation_table_lower[strpos('abcdefghijklmnopqrstuvwxyz', $char)];
            } elseif (strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ', $char) !== false) {
                $result_list[] = $translation_table_upper[strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ', $char)];
            } elseif (strpos($digits, $char) !== false) {
                $result_list[] = chr(((13 - (ord($char) - 48)) % 10) + 48);
            } else {
                $result_list[] = $char;
            }
        }

        return implode('', $result_list);
    }

    public static function passphrase($auth) {
        if (strlen($auth) != 32) {
            throw new Exception('auth length should be 32 digits');
        }

        $result_list = [];
        $chunks = str_split($auth, 8);
        $character_order = $chunks[2] . $chunks[0] . $chunks[3] . $chunks[1];

        for ($i = 0; $i < strlen($character_order); $i++) {
            $character = $character_order[$i];
            $result_list[] = chr(((ord($character) - 97 + 9) % 26) + 97);
        }

        return implode('', $result_list);
    }

    public static function secret($length) {
        $characters = 'abcdefghijklmnopqrstuvwxyz';
        $result = '';
        for ($i = 0; $i < $length; $i++) {
            $result .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $result;
    }

    public static function decrypt($data, $key) {
        $decoded_data = base64_decode($data);
        $cipher = openssl_decrypt($decoded_data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, self::AES_IV);
        $result = json_decode($cipher, true);
        return $result;
    }

    public static function encrypt($data, $key) {
        if (!is_string($data)) {
            $data = json_encode($data);
        }

        $padding = 16 - (strlen($data) % 16);
        $data .= str_repeat(chr($padding), $padding);

        $cipher = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, self::AES_IV);
        return base64_encode($cipher);
    }

    public static function sign($private_key, $data) {
        $key = openssl_pkey_get_private($private_key);
        openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);
        openssl_free_key($key);
        return base64_encode($signature);
    }

    public static function create_keys() {
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 1024,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $private_key);
        $public_key = openssl_pkey_get_details($res)['key'];
        return array(base64_encode($public_key), $private_key);
    }

    public static function decrypt_RSA_OAEP($private_key, $data) {
        $private_key = openssl_pkey_get_private($private_key);
        openssl_private_decrypt(base64_decode($data), $decrypted, $private_key, OPENSSL_PKCS1_OAEP_PADDING);
        return $decrypted;
    }
}
?>
