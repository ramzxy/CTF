# Web 2 Doc 2

**Category:** web | **Points:** 491 | **Flag:** `ENO{weasy_pr1nt_can_h4v3_f1l3s_1n_PDF_att4chments!}`

## Overview
A Flask URL-to-PDF converter using WeasyPrint. Same as v1 but with the `/admin/flag` oracle endpoint removed. Goal: read `/flag.txt`.

## Solution
The server validates the submitted URL (blocks `file://`, localhost, etc.) then fetches the HTML and renders it to PDF using WeasyPrint.

Key insight: **WeasyPrint supports `<link rel="attachment">`** which embeds arbitrary files as PDF attachments. While the URL validator blocks direct `file://` URLs, it doesn't restrict what URLs appear inside the fetched HTML content.

1. Host an HTML page externally (e.g., on `0x0.st`) containing:
   ```html
   <link rel="attachment" href="file:///flag.txt" title="flag">
   ```
2. Submit the hosted URL to the converter
3. WeasyPrint processes the HTML and embeds `/flag.txt` as a PDF attachment
4. Extract the attachment with `pdfdetach -save 1 output.pdf`

## Key Takeaways
- WeasyPrint's `<link rel="attachment">` can embed arbitrary local files into generated PDFs.
- URL validation on the initial request doesn't protect against file references within the fetched HTML.
- Always check PDF attachments (`pdfdetach -list`) when dealing with PDF-based challenges.
