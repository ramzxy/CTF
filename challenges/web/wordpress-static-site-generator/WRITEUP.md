# WordPress Static Site Generator

**Category:** web | **Points:** 449 | **Flag:** `ENO{PONGO2_T3MPl4T3_1NJ3cT1on_!s_Fun_To00!}`

## Overview
A Go web app using Pongo2 templates that converts WordPress XML exports into static HTML sites.

## Solution
Two vulnerabilities chained together:

1. **Unrestricted file upload** - The `/upload` endpoint accepts any file despite being labeled for XML uploads. Uploading a file named `evil.html` with Pongo2 template code works fine.

2. **Path traversal in template selection** - The `/generate` endpoint takes a `template` parameter and loads `templates/<template>.html`. No sanitization on `../`, so `template=../uploads/<id>/evil` loads `templates/../uploads/<id>/evil.html`.

Attack:
1. Upload a file named `evil.html` containing `{% include "/flag.txt" %}`
2. Note the upload directory from the response (`uploads/<hash>/`)
3. Generate with `template=../uploads/<hash>/evil` to load the uploaded file as a Pongo2 template
4. Pongo2 processes the `{% include %}` tag and reads `/flag.txt`

## Key Takeaways
- Pongo2 `{% include %}` can read arbitrary files from the filesystem.
- Path traversal + file upload = template injection when the app loads templates by user-controlled path.
- Always check if uploaded files can be referenced by other endpoints.
