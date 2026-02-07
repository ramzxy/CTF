<?php


class FlagEncryptor {
    private $key;

    public function __construct($randomKey) {
        $this->key = $randomKey;
    }


    public static function generateRandomKey($length = 16) {
        $key = '';
        $fp = fopen('/dev/urandom', 'rb');

        if ($fp !== false) {
            while (strlen($key) < $length) {
                $byte = fread($fp, 1);
                $ord = ord($byte);
                if ($ord >= 33 && $ord <= 126) {
                    $key .= $byte;
                }
            }
            fclose($fp);
        } else {
            $printableChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~';
            $numChars = strlen($printableChars);
            for ($i = 0; $i < $length; $i++) {
                $randomIndex = random_int(0, $numChars - 1);
                $key .= $printableChars[$randomIndex];
            }
        }

        return $key;
    }

    public function encrypt($plaintext) {
        $length = strlen($plaintext);
        $keyLength = strlen($this->key);
        $processed = '';

        for ($i = 0; $i < $length; $i++) {
            $keyChar = $this->key[$i % $keyLength];
            $processedKeyAscii = ord($keyChar);

        if ($keyChar == chr(0)) {
            $processedKeyAscii = ord($keyChar) + 26;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(1)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(2)) {
            $processedKeyAscii = ord($keyChar) + 55;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(3)) {
            $processedKeyAscii = ord($keyChar) + 26;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(4)) {
            $processedKeyAscii = ord($keyChar) + 78;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(5)) {
            $processedKeyAscii = ord($keyChar) + 31;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(6)) {
            $processedKeyAscii = ord($keyChar) + 30;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(7)) {
            $processedKeyAscii = ord($keyChar) + 98;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(8)) {
            $processedKeyAscii = ord($keyChar) + 77;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(9)) {
            $processedKeyAscii = ord($keyChar) + 12;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(10)) {
            $processedKeyAscii = ord($keyChar) + 51;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(11)) {
            $processedKeyAscii = ord($keyChar) + 64;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(12)) {
            $processedKeyAscii = ord($keyChar) + 73;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(13)) {
            $processedKeyAscii = ord($keyChar) + 68;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(14)) {
            $processedKeyAscii = ord($keyChar) + 33;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(15)) {
            $processedKeyAscii = ord($keyChar) + 11;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(16)) {
            $processedKeyAscii = ord($keyChar) + 87;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(17)) {
            $processedKeyAscii = ord($keyChar) + 12;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(18)) {
            $processedKeyAscii = ord($keyChar) + 62;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(19)) {
            $processedKeyAscii = ord($keyChar) + 75;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(20)) {
            $processedKeyAscii = ord($keyChar) + 68;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(21)) {
            $processedKeyAscii = ord($keyChar) + 9;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(22)) {
            $processedKeyAscii = ord($keyChar) + 42;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(23)) {
            $processedKeyAscii = ord($keyChar) + 41;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(24)) {
            $processedKeyAscii = ord($keyChar) + 35;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(25)) {
            $processedKeyAscii = ord($keyChar) + 29;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(26)) {
            $processedKeyAscii = ord($keyChar) + 76;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(27)) {
            $processedKeyAscii = ord($keyChar) + 27;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(28)) {
            $processedKeyAscii = ord($keyChar) + 76;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(29)) {
            $processedKeyAscii = ord($keyChar) + 85;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(30)) {
            $processedKeyAscii = ord($keyChar) + 87;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(31)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(32)) {
            $processedKeyAscii = ord($keyChar) + 25;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(33)) {
            $processedKeyAscii = ord($keyChar) + 41;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(34)) {
            $processedKeyAscii = ord($keyChar) + 99;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(35)) {
            $processedKeyAscii = ord($keyChar) + 40;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(36)) {
            $processedKeyAscii = ord($keyChar) + 21;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(37)) {
            $processedKeyAscii = ord($keyChar) + 47;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(38)) {
            $processedKeyAscii = ord($keyChar) + 42;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(39)) {
            $processedKeyAscii = ord($keyChar) + 41;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(40)) {
            $processedKeyAscii = ord($keyChar) + 34;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(41)) {
            $processedKeyAscii = ord($keyChar) + 70;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(42)) {
            $processedKeyAscii = ord($keyChar) + 46;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(43)) {
            $processedKeyAscii = ord($keyChar) + 38;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(44)) {
            $processedKeyAscii = ord($keyChar) + 62;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(45)) {
            $processedKeyAscii = ord($keyChar) + 7;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(46)) {
            $processedKeyAscii = ord($keyChar) + 77;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(47)) {
            $processedKeyAscii = ord($keyChar) + 12;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(48)) {
            $processedKeyAscii = ord($keyChar) + 14;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(49)) {
            $processedKeyAscii = ord($keyChar) + 34;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(50)) {
            $processedKeyAscii = ord($keyChar) + 24;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(51)) {
            $processedKeyAscii = ord($keyChar) + 87;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(52)) {
            $processedKeyAscii = ord($keyChar) + 43;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(53)) {
            $processedKeyAscii = ord($keyChar) + 83;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(54)) {
            $processedKeyAscii = ord($keyChar) + 68;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(55)) {
            $processedKeyAscii = ord($keyChar) + 76;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(56)) {
            $processedKeyAscii = ord($keyChar) + 20;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(57)) {
            $processedKeyAscii = ord($keyChar) + 53;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(58)) {
            $processedKeyAscii = ord($keyChar) + 33;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(59)) {
            $processedKeyAscii = ord($keyChar) + 51;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(60)) {
            $processedKeyAscii = ord($keyChar) + 83;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(61)) {
            $processedKeyAscii = ord($keyChar) + 9;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(62)) {
            $processedKeyAscii = ord($keyChar) + 11;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(63)) {
            $processedKeyAscii = ord($keyChar) + 48;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(64)) {
            $processedKeyAscii = ord($keyChar) + 51;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(65)) {
            $processedKeyAscii = ord($keyChar) + 71;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(66)) {
            $processedKeyAscii = ord($keyChar) + 76;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(67)) {
            $processedKeyAscii = ord($keyChar) + 28;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(68)) {
            $processedKeyAscii = ord($keyChar) + 33;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(69)) {
            $processedKeyAscii = ord($keyChar) + 76;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(70)) {
            $processedKeyAscii = ord($keyChar) + 51;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(71)) {
            $processedKeyAscii = ord($keyChar) + 37;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(72)) {
            $processedKeyAscii = ord($keyChar) + 96;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(73)) {
            $processedKeyAscii = ord($keyChar) + 53;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(74)) {
            $processedKeyAscii = ord($keyChar) + 90;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(75)) {
            $processedKeyAscii = ord($keyChar) + 26;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(76)) {
            $processedKeyAscii = ord($keyChar) + 19;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(77)) {
            $processedKeyAscii = ord($keyChar) + 65;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(78)) {
            $processedKeyAscii = ord($keyChar) + 96;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(79)) {
            $processedKeyAscii = ord($keyChar) + 63;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(80)) {
            $processedKeyAscii = ord($keyChar) + 87;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(81)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(82)) {
            $processedKeyAscii = ord($keyChar) + 28;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(83)) {
            $processedKeyAscii = ord($keyChar) + 38;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(84)) {
            $processedKeyAscii = ord($keyChar) + 63;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(85)) {
            $processedKeyAscii = ord($keyChar) + 85;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(86)) {
            $processedKeyAscii = ord($keyChar) + 64;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(87)) {
            $processedKeyAscii = ord($keyChar) + 28;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(88)) {
            $processedKeyAscii = ord($keyChar) + 34;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(89)) {
            $processedKeyAscii = ord($keyChar) + 24;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(90)) {
            $processedKeyAscii = ord($keyChar) + 33;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(91)) {
            $processedKeyAscii = ord($keyChar) + 18;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(92)) {
            $processedKeyAscii = ord($keyChar) + 29;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(93)) {
            $processedKeyAscii = ord($keyChar) + 99;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(94)) {
            $processedKeyAscii = ord($keyChar) + 50;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(95)) {
            $processedKeyAscii = ord($keyChar) + 73;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(96)) {
            $processedKeyAscii = ord($keyChar) + 26;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(97)) {
            $processedKeyAscii = ord($keyChar) + 34;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(98)) {
            $processedKeyAscii = ord($keyChar) + 14;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(99)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(100)) {
            $processedKeyAscii = ord($keyChar) + 38;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(101)) {
            $processedKeyAscii = ord($keyChar) + 81;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(102)) {
            $processedKeyAscii = ord($keyChar) + 42;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(103)) {
            $processedKeyAscii = ord($keyChar) + 69;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(104)) {
            $processedKeyAscii = ord($keyChar) + 59;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(105)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(106)) {
            $processedKeyAscii = ord($keyChar) + 20;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(107)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(108)) {
            $processedKeyAscii = ord($keyChar) + 66;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(109)) {
            $processedKeyAscii = ord($keyChar) + 83;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(110)) {
            $processedKeyAscii = ord($keyChar) + 98;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(111)) {
            $processedKeyAscii = ord($keyChar) + 24;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(112)) {
            $processedKeyAscii = ord($keyChar) + 76;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(113)) {
            $processedKeyAscii = ord($keyChar) + 80;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(114)) {
            $processedKeyAscii = ord($keyChar) + 86;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(115)) {
            $processedKeyAscii = ord($keyChar) + 13;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(116)) {
            $processedKeyAscii = ord($keyChar) + 29;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(117)) {
            $processedKeyAscii = ord($keyChar) + 15;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(118)) {
            $processedKeyAscii = ord($keyChar) + 54;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(119)) {
            $processedKeyAscii = ord($keyChar) + 75;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(120)) {
            $processedKeyAscii = ord($keyChar) + 17;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(121)) {
            $processedKeyAscii = ord($keyChar) + 17;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(122)) {
            $processedKeyAscii = ord($keyChar) + 49;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(123)) {
            $processedKeyAscii = ord($keyChar) + 83;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(124)) {
            $processedKeyAscii = ord($keyChar) + 96;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(125)) {
            $processedKeyAscii = ord($keyChar) + 41;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(126)) {
            $processedKeyAscii = ord($keyChar) + 54;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(127)) {
            $processedKeyAscii = ord($keyChar) + 82;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(128)) {
            $processedKeyAscii = ord($keyChar) + 42;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(129)) {
            $processedKeyAscii = ord($keyChar) + 47;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(130)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(131)) {
            $processedKeyAscii = ord($keyChar) + 7;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(132)) {
            $processedKeyAscii = ord($keyChar) + 8;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(133)) {
            $processedKeyAscii = ord($keyChar) + 82;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(134)) {
            $processedKeyAscii = ord($keyChar) + 92;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(135)) {
            $processedKeyAscii = ord($keyChar) + 93;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(136)) {
            $processedKeyAscii = ord($keyChar) + 71;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(137)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(138)) {
            $processedKeyAscii = ord($keyChar) + 51;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(139)) {
            $processedKeyAscii = ord($keyChar) + 82;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(140)) {
            $processedKeyAscii = ord($keyChar) + 16;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(141)) {
            $processedKeyAscii = ord($keyChar) + 63;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(142)) {
            $processedKeyAscii = ord($keyChar) + 79;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(143)) {
            $processedKeyAscii = ord($keyChar) + 11;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(144)) {
            $processedKeyAscii = ord($keyChar) + 75;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(145)) {
            $processedKeyAscii = ord($keyChar) + 72;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(146)) {
            $processedKeyAscii = ord($keyChar) + 93;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(147)) {
            $processedKeyAscii = ord($keyChar) + 33;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(148)) {
            $processedKeyAscii = ord($keyChar) + 18;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(149)) {
            $processedKeyAscii = ord($keyChar) + 80;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(150)) {
            $processedKeyAscii = ord($keyChar) + 64;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(151)) {
            $processedKeyAscii = ord($keyChar) + 27;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(152)) {
            $processedKeyAscii = ord($keyChar) + 92;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(153)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(154)) {
            $processedKeyAscii = ord($keyChar) + 30;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(155)) {
            $processedKeyAscii = ord($keyChar) + 87;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(156)) {
            $processedKeyAscii = ord($keyChar) + 34;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(157)) {
            $processedKeyAscii = ord($keyChar) + 92;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(158)) {
            $processedKeyAscii = ord($keyChar) + 21;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(159)) {
            $processedKeyAscii = ord($keyChar) + 86;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(160)) {
            $processedKeyAscii = ord($keyChar) + 58;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(161)) {
            $processedKeyAscii = ord($keyChar) + 7;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(162)) {
            $processedKeyAscii = ord($keyChar) + 17;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(163)) {
            $processedKeyAscii = ord($keyChar) + 91;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(164)) {
            $processedKeyAscii = ord($keyChar) + 79;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(165)) {
            $processedKeyAscii = ord($keyChar) + 78;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(166)) {
            $processedKeyAscii = ord($keyChar) + 98;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(167)) {
            $processedKeyAscii = ord($keyChar) + 70;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(168)) {
            $processedKeyAscii = ord($keyChar) + 44;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(169)) {
            $processedKeyAscii = ord($keyChar) + 88;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(170)) {
            $processedKeyAscii = ord($keyChar) + 57;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(171)) {
            $processedKeyAscii = ord($keyChar) + 20;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(172)) {
            $processedKeyAscii = ord($keyChar) + 80;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(173)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(174)) {
            $processedKeyAscii = ord($keyChar) + 64;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(175)) {
            $processedKeyAscii = ord($keyChar) + 79;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(176)) {
            $processedKeyAscii = ord($keyChar) + 69;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(177)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(178)) {
            $processedKeyAscii = ord($keyChar) + 46;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(179)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(180)) {
            $processedKeyAscii = ord($keyChar) + 25;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(181)) {
            $processedKeyAscii = ord($keyChar) + 25;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(182)) {
            $processedKeyAscii = ord($keyChar) + 33;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(183)) {
            $processedKeyAscii = ord($keyChar) + 86;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(184)) {
            $processedKeyAscii = ord($keyChar) + 34;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(185)) {
            $processedKeyAscii = ord($keyChar) + 31;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(186)) {
            $processedKeyAscii = ord($keyChar) + 78;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(187)) {
            $processedKeyAscii = ord($keyChar) + 78;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(188)) {
            $processedKeyAscii = ord($keyChar) + 47;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(189)) {
            $processedKeyAscii = ord($keyChar) + 21;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(190)) {
            $processedKeyAscii = ord($keyChar) + 94;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(191)) {
            $processedKeyAscii = ord($keyChar) + 58;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(192)) {
            $processedKeyAscii = ord($keyChar) + 36;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(193)) {
            $processedKeyAscii = ord($keyChar) + 34;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(194)) {
            $processedKeyAscii = ord($keyChar) + 26;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(195)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(196)) {
            $processedKeyAscii = ord($keyChar) + 85;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(197)) {
            $processedKeyAscii = ord($keyChar) + 74;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(198)) {
            $processedKeyAscii = ord($keyChar) + 86;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(199)) {
            $processedKeyAscii = ord($keyChar) + 46;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(200)) {
            $processedKeyAscii = ord($keyChar) + 47;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(201)) {
            $processedKeyAscii = ord($keyChar) + 84;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(202)) {
            $processedKeyAscii = ord($keyChar) + 68;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(203)) {
            $processedKeyAscii = ord($keyChar) + 29;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(204)) {
            $processedKeyAscii = ord($keyChar) + 88;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(205)) {
            $processedKeyAscii = ord($keyChar) + 36;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(206)) {
            $processedKeyAscii = ord($keyChar) + 65;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(207)) {
            $processedKeyAscii = ord($keyChar) + 9;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(208)) {
            $processedKeyAscii = ord($keyChar) + 13;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(209)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(210)) {
            $processedKeyAscii = ord($keyChar) + 95;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(211)) {
            $processedKeyAscii = ord($keyChar) + 51;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(212)) {
            $processedKeyAscii = ord($keyChar) + 94;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(213)) {
            $processedKeyAscii = ord($keyChar) + 79;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(214)) {
            $processedKeyAscii = ord($keyChar) + 12;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(215)) {
            $processedKeyAscii = ord($keyChar) + 43;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(216)) {
            $processedKeyAscii = ord($keyChar) + 89;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(217)) {
            $processedKeyAscii = ord($keyChar) + 49;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(218)) {
            $processedKeyAscii = ord($keyChar) + 32;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(219)) {
            $processedKeyAscii = ord($keyChar) + 82;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(220)) {
            $processedKeyAscii = ord($keyChar) + 87;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(221)) {
            $processedKeyAscii = ord($keyChar) + 63;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(222)) {
            $processedKeyAscii = ord($keyChar) + 95;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(223)) {
            $processedKeyAscii = ord($keyChar) + 7;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(224)) {
            $processedKeyAscii = ord($keyChar) + 54;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(225)) {
            $processedKeyAscii = ord($keyChar) + 66;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(226)) {
            $processedKeyAscii = ord($keyChar) + 48;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(227)) {
            $processedKeyAscii = ord($keyChar) + 11;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(228)) {
            $processedKeyAscii = ord($keyChar) + 89;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(229)) {
            $processedKeyAscii = ord($keyChar) + 74;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(230)) {
            $processedKeyAscii = ord($keyChar) + 76;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(231)) {
            $processedKeyAscii = ord($keyChar) + 78;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(232)) {
            $processedKeyAscii = ord($keyChar) + 57;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(233)) {
            $processedKeyAscii = ord($keyChar) + 49;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(234)) {
            $processedKeyAscii = ord($keyChar) + 22;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(235)) {
            $processedKeyAscii = ord($keyChar) + 59;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(236)) {
            $processedKeyAscii = ord($keyChar) + 58;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(237)) {
            $processedKeyAscii = ord($keyChar) + 36;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(238)) {
            $processedKeyAscii = ord($keyChar) + 43;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(239)) {
            $processedKeyAscii = ord($keyChar) + 78;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(240)) {
            $processedKeyAscii = ord($keyChar) + 25;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(241)) {
            $processedKeyAscii = ord($keyChar) + 48;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(242)) {
            $processedKeyAscii = ord($keyChar) + 77;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(243)) {
            $processedKeyAscii = ord($keyChar) + 28;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(244)) {
            $processedKeyAscii = ord($keyChar) + 15;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(245)) {
            $processedKeyAscii = ord($keyChar) + 69;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(246)) {
            $processedKeyAscii = ord($keyChar) + 7;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(247)) {
            $processedKeyAscii = ord($keyChar) + 20;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(248)) {
            $processedKeyAscii = ord($keyChar) + 67;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(249)) {
            $processedKeyAscii = ord($keyChar) + 94;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(250)) {
            $processedKeyAscii = ord($keyChar) + 61;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(251)) {
            $processedKeyAscii = ord($keyChar) + 35;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(252)) {
            $processedKeyAscii = ord($keyChar) + 70;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(253)) {
            $processedKeyAscii = ord($keyChar) + 49;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(254)) {
            $processedKeyAscii = ord($keyChar) + 12;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }
        else if ($keyChar == chr(255)) {
            $processedKeyAscii = ord($keyChar) + 16;
            if ($processedKeyAscii >= 256) {
                $processedKeyAscii = $processedKeyAscii - 256;
            }
        }

            $processedKey = chr($processedKeyAscii);

            $plaintextChar = $plaintext[$i];
            $xored = chr(ord($plaintextChar) ^ ord($processedKey));

            $finalAscii = ord($xored);

        if ($xored == chr(0)) {
            $finalAscii = ord($xored) + 26;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(1)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(2)) {
            $finalAscii = ord($xored) + 55;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(3)) {
            $finalAscii = ord($xored) + 26;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(4)) {
            $finalAscii = ord($xored) + 78;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(5)) {
            $finalAscii = ord($xored) + 31;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(6)) {
            $finalAscii = ord($xored) + 30;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(7)) {
            $finalAscii = ord($xored) + 98;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(8)) {
            $finalAscii = ord($xored) + 77;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(9)) {
            $finalAscii = ord($xored) + 12;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(10)) {
            $finalAscii = ord($xored) + 51;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(11)) {
            $finalAscii = ord($xored) + 64;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(12)) {
            $finalAscii = ord($xored) + 73;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(13)) {
            $finalAscii = ord($xored) + 68;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(14)) {
            $finalAscii = ord($xored) + 33;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(15)) {
            $finalAscii = ord($xored) + 11;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(16)) {
            $finalAscii = ord($xored) + 87;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(17)) {
            $finalAscii = ord($xored) + 12;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(18)) {
            $finalAscii = ord($xored) + 62;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(19)) {
            $finalAscii = ord($xored) + 75;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(20)) {
            $finalAscii = ord($xored) + 68;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(21)) {
            $finalAscii = ord($xored) + 9;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(22)) {
            $finalAscii = ord($xored) + 42;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(23)) {
            $finalAscii = ord($xored) + 41;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(24)) {
            $finalAscii = ord($xored) + 35;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(25)) {
            $finalAscii = ord($xored) + 29;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(26)) {
            $finalAscii = ord($xored) + 76;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(27)) {
            $finalAscii = ord($xored) + 27;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(28)) {
            $finalAscii = ord($xored) + 76;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(29)) {
            $finalAscii = ord($xored) + 85;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(30)) {
            $finalAscii = ord($xored) + 87;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(31)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(32)) {
            $finalAscii = ord($xored) + 25;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(33)) {
            $finalAscii = ord($xored) + 41;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(34)) {
            $finalAscii = ord($xored) + 99;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(35)) {
            $finalAscii = ord($xored) + 40;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(36)) {
            $finalAscii = ord($xored) + 21;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(37)) {
            $finalAscii = ord($xored) + 47;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(38)) {
            $finalAscii = ord($xored) + 42;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(39)) {
            $finalAscii = ord($xored) + 41;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(40)) {
            $finalAscii = ord($xored) + 34;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(41)) {
            $finalAscii = ord($xored) + 70;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(42)) {
            $finalAscii = ord($xored) + 46;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(43)) {
            $finalAscii = ord($xored) + 38;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(44)) {
            $finalAscii = ord($xored) + 62;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(45)) {
            $finalAscii = ord($xored) + 7;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(46)) {
            $finalAscii = ord($xored) + 77;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(47)) {
            $finalAscii = ord($xored) + 12;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(48)) {
            $finalAscii = ord($xored) + 14;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(49)) {
            $finalAscii = ord($xored) + 34;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(50)) {
            $finalAscii = ord($xored) + 24;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(51)) {
            $finalAscii = ord($xored) + 87;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(52)) {
            $finalAscii = ord($xored) + 43;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(53)) {
            $finalAscii = ord($xored) + 83;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(54)) {
            $finalAscii = ord($xored) + 68;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(55)) {
            $finalAscii = ord($xored) + 76;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(56)) {
            $finalAscii = ord($xored) + 20;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(57)) {
            $finalAscii = ord($xored) + 53;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(58)) {
            $finalAscii = ord($xored) + 33;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(59)) {
            $finalAscii = ord($xored) + 51;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(60)) {
            $finalAscii = ord($xored) + 83;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(61)) {
            $finalAscii = ord($xored) + 9;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(62)) {
            $finalAscii = ord($xored) + 11;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(63)) {
            $finalAscii = ord($xored) + 48;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(64)) {
            $finalAscii = ord($xored) + 51;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(65)) {
            $finalAscii = ord($xored) + 71;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(66)) {
            $finalAscii = ord($xored) + 76;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(67)) {
            $finalAscii = ord($xored) + 28;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(68)) {
            $finalAscii = ord($xored) + 33;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(69)) {
            $finalAscii = ord($xored) + 76;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(70)) {
            $finalAscii = ord($xored) + 51;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(71)) {
            $finalAscii = ord($xored) + 37;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(72)) {
            $finalAscii = ord($xored) + 96;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(73)) {
            $finalAscii = ord($xored) + 53;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(74)) {
            $finalAscii = ord($xored) + 90;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(75)) {
            $finalAscii = ord($xored) + 26;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(76)) {
            $finalAscii = ord($xored) + 19;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(77)) {
            $finalAscii = ord($xored) + 65;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(78)) {
            $finalAscii = ord($xored) + 96;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(79)) {
            $finalAscii = ord($xored) + 63;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(80)) {
            $finalAscii = ord($xored) + 87;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(81)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(82)) {
            $finalAscii = ord($xored) + 28;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(83)) {
            $finalAscii = ord($xored) + 38;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(84)) {
            $finalAscii = ord($xored) + 63;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(85)) {
            $finalAscii = ord($xored) + 85;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(86)) {
            $finalAscii = ord($xored) + 64;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(87)) {
            $finalAscii = ord($xored) + 28;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(88)) {
            $finalAscii = ord($xored) + 34;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(89)) {
            $finalAscii = ord($xored) + 24;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(90)) {
            $finalAscii = ord($xored) + 33;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(91)) {
            $finalAscii = ord($xored) + 18;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(92)) {
            $finalAscii = ord($xored) + 29;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(93)) {
            $finalAscii = ord($xored) + 99;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(94)) {
            $finalAscii = ord($xored) + 50;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(95)) {
            $finalAscii = ord($xored) + 73;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(96)) {
            $finalAscii = ord($xored) + 26;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(97)) {
            $finalAscii = ord($xored) + 34;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(98)) {
            $finalAscii = ord($xored) + 14;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(99)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(100)) {
            $finalAscii = ord($xored) + 38;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(101)) {
            $finalAscii = ord($xored) + 81;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(102)) {
            $finalAscii = ord($xored) + 42;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(103)) {
            $finalAscii = ord($xored) + 69;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(104)) {
            $finalAscii = ord($xored) + 59;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(105)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(106)) {
            $finalAscii = ord($xored) + 20;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(107)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(108)) {
            $finalAscii = ord($xored) + 66;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(109)) {
            $finalAscii = ord($xored) + 83;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(110)) {
            $finalAscii = ord($xored) + 98;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(111)) {
            $finalAscii = ord($xored) + 24;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(112)) {
            $finalAscii = ord($xored) + 76;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(113)) {
            $finalAscii = ord($xored) + 80;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(114)) {
            $finalAscii = ord($xored) + 86;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(115)) {
            $finalAscii = ord($xored) + 13;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(116)) {
            $finalAscii = ord($xored) + 29;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(117)) {
            $finalAscii = ord($xored) + 15;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(118)) {
            $finalAscii = ord($xored) + 54;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(119)) {
            $finalAscii = ord($xored) + 75;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(120)) {
            $finalAscii = ord($xored) + 17;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(121)) {
            $finalAscii = ord($xored) + 17;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(122)) {
            $finalAscii = ord($xored) + 49;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(123)) {
            $finalAscii = ord($xored) + 83;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(124)) {
            $finalAscii = ord($xored) + 96;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(125)) {
            $finalAscii = ord($xored) + 41;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(126)) {
            $finalAscii = ord($xored) + 54;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(127)) {
            $finalAscii = ord($xored) + 82;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(128)) {
            $finalAscii = ord($xored) + 42;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(129)) {
            $finalAscii = ord($xored) + 47;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(130)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(131)) {
            $finalAscii = ord($xored) + 7;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(132)) {
            $finalAscii = ord($xored) + 8;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(133)) {
            $finalAscii = ord($xored) + 82;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(134)) {
            $finalAscii = ord($xored) + 92;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(135)) {
            $finalAscii = ord($xored) + 93;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(136)) {
            $finalAscii = ord($xored) + 71;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(137)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(138)) {
            $finalAscii = ord($xored) + 51;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(139)) {
            $finalAscii = ord($xored) + 82;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(140)) {
            $finalAscii = ord($xored) + 16;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(141)) {
            $finalAscii = ord($xored) + 63;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(142)) {
            $finalAscii = ord($xored) + 79;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(143)) {
            $finalAscii = ord($xored) + 11;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(144)) {
            $finalAscii = ord($xored) + 75;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(145)) {
            $finalAscii = ord($xored) + 72;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(146)) {
            $finalAscii = ord($xored) + 93;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(147)) {
            $finalAscii = ord($xored) + 33;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(148)) {
            $finalAscii = ord($xored) + 18;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(149)) {
            $finalAscii = ord($xored) + 80;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(150)) {
            $finalAscii = ord($xored) + 64;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(151)) {
            $finalAscii = ord($xored) + 27;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(152)) {
            $finalAscii = ord($xored) + 92;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(153)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(154)) {
            $finalAscii = ord($xored) + 30;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(155)) {
            $finalAscii = ord($xored) + 87;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(156)) {
            $finalAscii = ord($xored) + 34;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(157)) {
            $finalAscii = ord($xored) + 92;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(158)) {
            $finalAscii = ord($xored) + 21;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(159)) {
            $finalAscii = ord($xored) + 86;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(160)) {
            $finalAscii = ord($xored) + 58;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(161)) {
            $finalAscii = ord($xored) + 7;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(162)) {
            $finalAscii = ord($xored) + 17;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(163)) {
            $finalAscii = ord($xored) + 91;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(164)) {
            $finalAscii = ord($xored) + 79;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(165)) {
            $finalAscii = ord($xored) + 78;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(166)) {
            $finalAscii = ord($xored) + 98;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(167)) {
            $finalAscii = ord($xored) + 70;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(168)) {
            $finalAscii = ord($xored) + 44;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(169)) {
            $finalAscii = ord($xored) + 88;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(170)) {
            $finalAscii = ord($xored) + 57;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(171)) {
            $finalAscii = ord($xored) + 20;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(172)) {
            $finalAscii = ord($xored) + 80;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(173)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(174)) {
            $finalAscii = ord($xored) + 64;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(175)) {
            $finalAscii = ord($xored) + 79;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(176)) {
            $finalAscii = ord($xored) + 69;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(177)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(178)) {
            $finalAscii = ord($xored) + 46;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(179)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(180)) {
            $finalAscii = ord($xored) + 25;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(181)) {
            $finalAscii = ord($xored) + 25;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(182)) {
            $finalAscii = ord($xored) + 33;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(183)) {
            $finalAscii = ord($xored) + 86;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(184)) {
            $finalAscii = ord($xored) + 34;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(185)) {
            $finalAscii = ord($xored) + 31;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(186)) {
            $finalAscii = ord($xored) + 78;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(187)) {
            $finalAscii = ord($xored) + 78;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(188)) {
            $finalAscii = ord($xored) + 47;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(189)) {
            $finalAscii = ord($xored) + 21;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(190)) {
            $finalAscii = ord($xored) + 94;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(191)) {
            $finalAscii = ord($xored) + 58;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(192)) {
            $finalAscii = ord($xored) + 36;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(193)) {
            $finalAscii = ord($xored) + 34;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(194)) {
            $finalAscii = ord($xored) + 26;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(195)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(196)) {
            $finalAscii = ord($xored) + 85;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(197)) {
            $finalAscii = ord($xored) + 74;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(198)) {
            $finalAscii = ord($xored) + 86;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(199)) {
            $finalAscii = ord($xored) + 46;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(200)) {
            $finalAscii = ord($xored) + 47;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(201)) {
            $finalAscii = ord($xored) + 84;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(202)) {
            $finalAscii = ord($xored) + 68;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(203)) {
            $finalAscii = ord($xored) + 29;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(204)) {
            $finalAscii = ord($xored) + 88;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(205)) {
            $finalAscii = ord($xored) + 36;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(206)) {
            $finalAscii = ord($xored) + 65;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(207)) {
            $finalAscii = ord($xored) + 9;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(208)) {
            $finalAscii = ord($xored) + 13;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(209)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(210)) {
            $finalAscii = ord($xored) + 95;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(211)) {
            $finalAscii = ord($xored) + 51;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(212)) {
            $finalAscii = ord($xored) + 94;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(213)) {
            $finalAscii = ord($xored) + 79;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(214)) {
            $finalAscii = ord($xored) + 12;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(215)) {
            $finalAscii = ord($xored) + 43;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(216)) {
            $finalAscii = ord($xored) + 89;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(217)) {
            $finalAscii = ord($xored) + 49;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(218)) {
            $finalAscii = ord($xored) + 32;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(219)) {
            $finalAscii = ord($xored) + 82;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(220)) {
            $finalAscii = ord($xored) + 87;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(221)) {
            $finalAscii = ord($xored) + 63;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(222)) {
            $finalAscii = ord($xored) + 95;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(223)) {
            $finalAscii = ord($xored) + 7;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(224)) {
            $finalAscii = ord($xored) + 54;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(225)) {
            $finalAscii = ord($xored) + 66;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(226)) {
            $finalAscii = ord($xored) + 48;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(227)) {
            $finalAscii = ord($xored) + 11;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(228)) {
            $finalAscii = ord($xored) + 89;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(229)) {
            $finalAscii = ord($xored) + 74;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(230)) {
            $finalAscii = ord($xored) + 76;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(231)) {
            $finalAscii = ord($xored) + 78;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(232)) {
            $finalAscii = ord($xored) + 57;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(233)) {
            $finalAscii = ord($xored) + 49;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(234)) {
            $finalAscii = ord($xored) + 22;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(235)) {
            $finalAscii = ord($xored) + 59;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(236)) {
            $finalAscii = ord($xored) + 58;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(237)) {
            $finalAscii = ord($xored) + 36;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(238)) {
            $finalAscii = ord($xored) + 43;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(239)) {
            $finalAscii = ord($xored) + 78;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(240)) {
            $finalAscii = ord($xored) + 25;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(241)) {
            $finalAscii = ord($xored) + 48;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(242)) {
            $finalAscii = ord($xored) + 77;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(243)) {
            $finalAscii = ord($xored) + 28;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(244)) {
            $finalAscii = ord($xored) + 15;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(245)) {
            $finalAscii = ord($xored) + 69;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(246)) {
            $finalAscii = ord($xored) + 7;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(247)) {
            $finalAscii = ord($xored) + 20;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(248)) {
            $finalAscii = ord($xored) + 67;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(249)) {
            $finalAscii = ord($xored) + 94;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(250)) {
            $finalAscii = ord($xored) + 61;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(251)) {
            $finalAscii = ord($xored) + 35;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(252)) {
            $finalAscii = ord($xored) + 70;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(253)) {
            $finalAscii = ord($xored) + 49;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(254)) {
            $finalAscii = ord($xored) + 12;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }
        else if ($xored == chr(255)) {
            $finalAscii = ord($xored) + 16;
            if ($finalAscii >= 256) {
                $finalAscii = $finalAscii - 256;
            }
        }

            $processed .= chr($finalAscii);
        }

        $base64 = base64_encode($processed);
        $crc = sha1($processed);
        return $base64 . ':' . $crc;
    }
}


if (realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    if (php_sapi_name() === 'cli') {
        if ($argc < 2) {
            echo "Usage: php encrypt.php <flag>\n";
            exit(1);
        }

        $flag = $argv[1];
        $randomKey = FlagEncryptor::generateRandomKey(16);

        $encryptor = new FlagEncryptor($randomKey);
        $encrypted = $encryptor->encrypt($flag);

        echo "Encrypted: " . $encrypted . "\n";
        echo "Key (hex): " . bin2hex($randomKey) . "\n";
    } else {

        $flag = isset($_POST['flag']) ? $_POST['flag'] : '';

        if ($flag) {
            $randomKey = FlagEncryptor::generateRandomKey(16);
            $encryptor = new FlagEncryptor($randomKey);
            $encrypted = $encryptor->encrypt($flag);

            echo json_encode(['encrypted' => $encrypted]);
        }
    }
}
