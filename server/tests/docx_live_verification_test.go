package tests

import "testing"

func TestDOCXSensitiveContentLiveGateway(t *testing.T) {
	testOOXMLSensitiveContentLiveGateway(t, liveOOXMLFormat{
		Extension: "docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		Filename: "minutes.docx", Marker: "wdsp-file-test-dlive", Field: "hdr.p.r.t", Scope: "DOCX_HEADER_FOOTER",
		SourcePart: "word/header1.xml", Port: 18089, Fixture: docxLiveFixture,
	})
}

func docxLiveFixture(t *testing.T) []byte {
	t.Helper()
	return ooxmlLiveFixture(t, []struct{ name, body string }{
		{"word/document.xml", `<w:document><w:body><w:p><w:r><w:t>ordinary meeting notes</w:t></w:r></w:p></w:body></w:document>`},
		{"word/header1.xml", `<w:hdr><w:p><w:r><w:t>wdsp-file-test-dlive</w:t></w:r></w:p></w:hdr>`},
	})
}
