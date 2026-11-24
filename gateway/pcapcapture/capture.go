package pcapcapture

import (
	"io"
	"net/http"

	"github.com/google/gopacket/tcpassembly"
	"github.com/jiuzhang-waf/gateway/mirrorcap"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

type Capture = pcapevidence.Capture
type CaptureConfig = pcapevidence.CaptureConfig
type CaptureStats = pcapevidence.CaptureStats
type SealedSegment = pcapevidence.SealedSegment

type mirrorRequestHandler struct {
	linker *pcapevidence.RequestLinker
}

func (h mirrorRequestHandler) HandleRequest(request *http.Request, meta mirrorcap.FlowMeta, bodyTruncated bool) {
	h.linker.HandleRequest(request, pcapevidence.FlowMeta{
		SrcIP:   meta.SrcIP,
		SrcPort: meta.SrcPort,
		DstIP:   meta.DstIP,
		DstPort: meta.DstPort,
	}, bodyTruncated)
}

func NewCapture(config CaptureConfig) (*Capture, error) {
	config.FilesystemUID = 1000
	config.FilesystemGID = 1000
	config.RequestAssemblerFactory = func(linker *pcapevidence.RequestLinker) pcapevidence.RequestAssembler {
		factory := mirrorcap.NewStreamFactory(mirrorRequestHandler{linker: linker}, 64<<10, 4096, nil)
		return tcpassembly.NewAssembler(tcpassembly.NewStreamPool(factory))
	}
	return pcapevidence.NewCapture(config)
}

func NewPublicKeyDEKProvider(publicKey []byte) (*pcapevidence.PublicKeyDEKProvider, error) {
	return pcapevidence.NewPublicKeyDEKProvider(publicKey)
}

func VerifyAndDecrypt(path string, manifest pcapevidence.Manifest, key []byte, output io.Writer) error {
	return pcapevidence.VerifyAndDecrypt(path, manifest, key, output)
}
