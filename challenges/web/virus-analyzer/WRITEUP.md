# Virus Analyzer

**Category:** web | **Points:** 461 | **Flag:** `ENO{R4C1NG_UPL04D5_4R3_FUN}`

## Overview
A PHP web app that accepts ZIP uploads, extracts them, and lists the files with download links.

## Solution
The app extracts uploaded ZIP files into `/var/www/uploads/<random_hex>/` and serves them directly via the web server. Since PHP files are processed by the PHP interpreter, uploading a ZIP containing a PHP file gives arbitrary PHP code execution.

Process forking was disabled (`Cannot fork`), so `system()`/`passthru()` etc. couldn't spawn shells. However, PHP file functions (`file_get_contents`, `scandir`) worked fine. Uploaded a PHP script that reads `/flag.txt` directly.

```php
<?php echo file_get_contents("/flag.txt"); ?>
```

## Key Takeaways
- When ZIP contents are served from a PHP-enabled web root, uploaded `.php` files get executed.
- Even when process forking is disabled, native PHP file I/O functions still work for reading the flag.
- Always check what restrictions are in place (disabled functions, fork limits) and adapt.
