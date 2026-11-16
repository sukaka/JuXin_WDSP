package ingest

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

const (
	DefaultProduceTimeout  = 10 * time.Second
	DefaultMaxBatchBytes   = 4 << 20
	DefaultMaxBatchRecords = 100
)

type Config struct {
	Brokers           []string
	ClientID          string
	TLSEnabled        bool
	TLSCAFile         string
	TLSCertFile       string
	TLSKeyFile        string
	TLSServerName     string
	SASLMechanism     string
	SASLUsername      string
	SASLPassword      string
	AllowInsecureSASL bool
	ProduceTimeout    time.Duration
	MaxBatchBytes     int
	MaxBatchRecords   int
}

func (c Config) withDefaults() Config {
	if c.ClientID == "" {
		c.ClientID = "wdsp-server"
	}
	if c.ProduceTimeout == 0 {
		c.ProduceTimeout = DefaultProduceTimeout
	}
	if c.MaxBatchBytes == 0 {
		c.MaxBatchBytes = DefaultMaxBatchBytes
	}
	if c.MaxBatchRecords == 0 {
		c.MaxBatchRecords = DefaultMaxBatchRecords
	}
	return c
}

func (c Config) Validate() error {
	c = c.withDefaults()
	if len(c.Brokers) == 0 {
		return errors.New("kafka brokers are required")
	}
	for _, broker := range c.Brokers {
		if strings.TrimSpace(broker) == "" || len(broker) > 255 {
			return errors.New("kafka broker must be 1..255 characters")
		}
	}
	if c.ProduceTimeout <= 0 || c.ProduceTimeout > time.Minute {
		return errors.New("kafka produce timeout must be in (0,1m]")
	}
	if c.MaxBatchBytes <= 0 || c.MaxBatchBytes > 32<<20 {
		return errors.New("kafka max batch bytes must be in (0,32MiB]")
	}
	if c.MaxBatchRecords <= 0 || c.MaxBatchRecords > 10000 {
		return errors.New("kafka max batch records must be in (0,10000]")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("kafka TLS cert and key must be configured together")
	}
	mechanism := strings.ToUpper(strings.TrimSpace(c.SASLMechanism))
	switch mechanism {
	case "", "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512":
	default:
		return fmt.Errorf("unsupported kafka SASL mechanism %q", c.SASLMechanism)
	}
	if mechanism != "" {
		if c.SASLUsername == "" || c.SASLPassword == "" {
			return errors.New("kafka SASL username and password are required")
		}
		if !c.TLSEnabled && !c.AllowInsecureSASL {
			return errors.New("kafka SASL requires TLS unless insecure development mode is explicitly enabled")
		}
	}
	return nil
}

func (c Config) clientOptions() ([]kgo.Opt, error) {
	c = c.withDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.Brokers...),
		kgo.ClientID(c.ClientID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProduceRequestTimeout(c.ProduceTimeout),
		kgo.RecordDeliveryTimeout(c.ProduceTimeout + 5*time.Second),
		kgo.ProducerBatchCompression(kgo.SnappyCompression()),
		kgo.ProducerLinger(20 * time.Millisecond),
		kgo.FetchMaxBytes(8 << 20),
		kgo.FetchMaxWait(250 * time.Millisecond),
		kgo.MaxConcurrentFetches(1),
	}
	if c.TLSEnabled {
		tlsConfig, err := c.tlsConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.Dialer((&tls.Dialer{Config: tlsConfig}).DialContext))
	}
	switch strings.ToUpper(strings.TrimSpace(c.SASLMechanism)) {
	case "PLAIN":
		opts = append(opts, kgo.SASL(plain.Auth{User: c.SASLUsername, Pass: c.SASLPassword}.AsMechanism()))
	case "SCRAM-SHA-256":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.SASLUsername, Pass: c.SASLPassword}.AsSha256Mechanism()))
	case "SCRAM-SHA-512":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.SASLUsername, Pass: c.SASLPassword}.AsSha512Mechanism()))
	}
	return opts, nil
}

func (c Config) tlsConfig() (*tls.Config, error) {
	out := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.TLSServerName}
	if c.TLSCAFile != "" {
		pem, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read kafka CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("kafka CA contains no valid certificates")
		}
		out.RootCAs = pool
	}
	if c.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load kafka client certificate: %w", err)
		}
		out.Certificates = []tls.Certificate{cert}
	}
	return out, nil
}
