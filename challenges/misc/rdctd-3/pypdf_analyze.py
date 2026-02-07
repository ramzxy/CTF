import pypdf

reader = pypdf.PdfReader('files/Planned-Flags-signed-2.pdf')

print("--- Metadata ---")
for key, value in reader.metadata.items():
    print(f"{key}: {value}")

print("\n--- Attachments ---")
if hasattr(reader, 'attachments'):
    print(reader.attachments)
else:
    # Older pypdf versions or no attachments
    try:
        catalog = reader.trailer["/Root"]
        if "/Names" in catalog and "/EmbeddedFiles" in catalog["/Names"]:
            print("Found EmbeddedFiles but need manual extraction")
    except:
        pass

print("\n--- Annotations and Links ---")
for i, page in enumerate(reader.pages):
    print(f"Page {i+1}:")
    if "/Annots" in page:
        annots = page["/Annots"]
        for annot in annots:
            obj = annot.get_object()
            if "/A" in obj and "/URI" in obj["/A"]:
                print(f"  Link URI: {obj['/A']['/URI']}")
            if "/Contents" in obj:
                print(f"  Annot Contents: {obj['/Contents']}")
            if "/T" in obj: # Widget name?
                print(f"  Widget T: {obj['/T']}")
            # Sometimes flags are in the AP stream or hidden fields
            
    # Also extract text
    text = page.extract_text()
    if "ENO{" in text:
        print("  Found ENO in text:")
        start = text.find("ENO{")
        print(f"  {text[start:start+50]}...")
