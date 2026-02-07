<?php



if (!function_exists('xdebug_start_code_coverage')) {
    die("ERROR: xdebug extension is required to generate coverage data\n");
}

xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE | XDEBUG_CC_BRANCH_CHECK);

require_once 'encrypt.php';

$flag = trim(file_get_contents('flag.txt'));

$randomKey = FlagEncryptor::generateRandomKey(9);

$encryptor = new FlagEncryptor($randomKey);
$encrypted = $encryptor->encrypt($flag);

list($encryptedData, $checksum) = explode(':', $encrypted, 2);


$coverage = xdebug_get_code_coverage();
xdebug_stop_code_coverage();


$filteredCoverage = [];
foreach ($coverage as $file => $lines) {
    if (strpos($file, 'encrypt.php') !== false) {
        $filteredCoverage[$file] = $lines;
    }
}


if (!is_dir('output')) {
    mkdir('output', 0755, true);
}


file_put_contents('output/encrypted_flag.txt', $encrypted);


file_put_contents('output/key.txt', "Key (plain): " . $randomKey . "\n");
file_put_contents('output/key.txt', "Key (hex): " . bin2hex($randomKey) . "\n", FILE_APPEND);
file_put_contents('output/key.txt', "Key (base64): " . base64_encode($randomKey) . "\n", FILE_APPEND);


file_put_contents('output/coverage.json', json_encode($filteredCoverage, JSON_PRETTY_PRINT));