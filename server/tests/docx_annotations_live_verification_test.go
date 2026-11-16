package tests

import "testing"

func TestDOCXAnnotationsSensitiveContentLiveGateway(t *testing.T) {
	testOOXMLSensitiveContentLiveGateway(t, liveOOXMLFormat{
		Extension: "docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		Filename: "review.docx", Marker: "wdsp-file-test-clive", Field: "comments.comment.p.r.t", Scope: "DOCX_ANNOTATIONS",
		SourcePart: "word/comments.xml", Port: 18090, Fixture: docxAnnotationsLiveFixture,
	})
}

func docxAnnotationsLiveFixture(t *testing.T) []byte {
	t.Helper()
	return ooxmlLiveFixture(t, []struct{ name, body string }{
		{"word/document.xml", `<w:document><w:body><w:p><w:r><w:t>ordinary review document</w:t></w:r></w:p></w:body></w:document>`},
		{"word/comments.xml", `<w:comments><w:comment><w:p><w:r><w:t>wdsp-file-test-clive</w:t></w:r></w:p></w:comment></w:comments>`},
	})
}
