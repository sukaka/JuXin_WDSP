package jiuzhang_guard

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(&ConnectionMetrics{})
}

type connectionMetrics struct {
	acceptedTotal atomic.Uint64
	active        atomic.Int64
	bytesInTotal  atomic.Uint64
	bytesOutTotal atomic.Uint64
}

var globalConnectionMetrics = &connectionMetrics{}

// ConnectionMetrics counts accepted TCP connections without changing their behavior.
type ConnectionMetrics struct {
	metrics *connectionMetrics
}

func (ConnectionMetrics) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.jiuzhang_connection_metrics",
		New: func() caddy.Module { return new(ConnectionMetrics) },
	}
}

func (c *ConnectionMetrics) Provision(caddy.Context) error {
	c.metrics = globalConnectionMetrics
	return nil
}

func (c *ConnectionMetrics) WrapListener(listener net.Listener) net.Listener {
	metrics := c.metrics
	if metrics == nil {
		metrics = globalConnectionMetrics
	}
	return &countingListener{Listener: listener, metrics: metrics}
}

type countingListener struct {
	net.Listener
	metrics *connectionMetrics
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.metrics.acceptedTotal.Add(1)
	l.metrics.active.Add(1)
	return &countingConn{Conn: conn, metrics: l.metrics}, nil
}

type countingConn struct {
	net.Conn
	metrics *connectionMetrics
	once    sync.Once
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.metrics.bytesInTotal.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.metrics.bytesOutTotal.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.metrics.active.Add(-1) })
	return err
}

// NetConn exposes the underlying net.Conn so downstream wrappers (e.g. proxy_protocol / tls / syscall.Conn)
// can inspect or unwrap the original TCP connection.
func (c *countingConn) NetConn() net.Conn {
	return c.Conn
}

// Unwrap exposes the underlying net.Conn following Go standard unwrapping conventions.
func (c *countingConn) Unwrap() net.Conn {
	return c.Conn
}

var (
	_ caddy.Provisioner     = (*ConnectionMetrics)(nil)
	_ caddy.ListenerWrapper = (*ConnectionMetrics)(nil)
)
