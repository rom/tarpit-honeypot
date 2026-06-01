package cli

import (
	"archive/zip"
	"fmt"
	"html"
	"os"
)

// writeDocxCanary writes a minimal but valid .docx (Office Open XML, a ZIP)
// whose settings.xml references an *external* attached template at callbackURL.
// Word resolves an attachedTemplate relationship on open, issuing an outbound
// HTTP(S) GET to the URL — which an `ssrf_canary` (or any HTTP) listener
// records, telling the operator the bait document was opened and from where.
//
// The document body carries innocuous, enticing-looking text; the beacon is in
// the relationship, not the visible content. This is the classic "honeydoc":
// plant it in a share named like real sensitive data and the canary fires the
// moment someone opens it.
func writeDocxCanary(path, callbackURL string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)

	esc := html.EscapeString(callbackURL)
	files := []struct{ name, body string }{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", relsRootXML},
		{"word/document.xml", documentXML},
		{"word/_rels/document.xml.rels", fmt.Sprintf(documentRelsXML, esc)},
		{"word/settings.xml", settingsXML},
	}
	for _, file := range files {
		w, err := zw.Create(file.name)
		if err != nil {
			_ = zw.Close()
			return err
		}
		if _, err := w.Write([]byte(file.body)); err != nil {
			_ = zw.Close()
			return err
		}
	}
	return zw.Close()
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>`

const relsRootXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

const documentXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:r><w:t>CONFIDENTIAL — Q4 Financials and Credentials</w:t></w:r></w:p>
<w:p><w:r><w:t>This workbook contains the production database passwords and the AWS root keys. Do not distribute.</w:t></w:r></w:p>
</w:body>
</w:document>`

// documentRelsXML wires settings.xml in; settings.xml carries the external
// attachedTemplate relationship that beacons. The %s is the callback URL.
const documentRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
<Relationship Id="rIdT" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="%s" TargetMode="External"/>
</Relationships>`

const settingsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:attachedTemplate r:id="rIdT" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
</w:settings>`
