package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"sync"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
	"github.com/jiuzhang-waf/wdsp-agent/internal/apiobserve"
	"github.com/jiuzhang-waf/wdsp-agent/internal/inprocess"
)

type writer struct {
	processor *apiobserve.Processor
	file      *os.File
	mu        sync.Mutex
}

func (w *writer) ProcessBatch(batch apievent.CaptureBatch) ([]apievent.Record, error) {
	records, err := w.processor.ProcessBatch(batch)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, record := range records {
		if err := json.NewEncoder(w.file).Encode(record); err != nil {
			return nil, err
		}
	}
	return records, nil
}

func main() {
	socket := flag.String("socket", "/tmp/wdsp-cloud-agent.sock", "Unix socket")
	output := flag.String("output", "/tmp/wdsp-cloud-agent-observations.jsonl", "Output JSONL")
	flag.Parse()
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	server, err := inprocess.Listen(*socket, 0o600, &writer{processor: apiobserve.NewProcessor("cloud-e2e-agent", []byte("cloud-e2e-hmac-key"), "key-1"), file: file}, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := server.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
