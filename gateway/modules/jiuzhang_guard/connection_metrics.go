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

func (c *countingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.metrics.active.Add(-1) })
	return err
}

var (
	_ caddy.Provisioner     = (*ConnectionMetrics)(nil)
	_ caddy.ListenerWrapper = (*ConnectionMetrics)(nil)
)
