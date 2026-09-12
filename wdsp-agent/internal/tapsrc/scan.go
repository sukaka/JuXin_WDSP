// tap 管理流会话与 JSON 分帧（P1-03 §3.3：分帧/分片/半消息/重连）。
//
// Envoy streaming_admin（JSON_BODY_AS_BYTES）输出为美化 JSON 消息以换行
// 相接的字节流。分帧器按括号深度+字符串/转义状态机切帧：TCP 分片与半消息
// 由缓冲自然处理（不把一次 read 当成完整 JSON）；单消息超限时丢弃该条并
// 继续状态机同步后续帧（有界，不无界拼接）；TCP 字节流保序，不重排消息。
package tapsrc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// tapPostBody POST /tap 请求体（config_id + TapConfig JSON）。
// match any_match；streaming_admin sink；格式锁定 JSON_BODY_AS_BYTES
// （v1.35.3 二进制长度分帧格式会使 Envoy 崩溃，见包注释 S0 结论）。
type tapPostBody struct {
	ConfigID  string        `json:"config_id"`
	TapConfig tapPostConfig `json:"tap_config"`
}

type tapPostConfig struct {
	MatchConfig  tapMatchConfig  `json:"match_config"`
	OutputConfig tapOutputConfig `json:"output_config"`
}

type tapMatchConfig struct {
	AnyMatch bool `json:"any_match"`
}

type tapOutputConfig struct {
	Sinks              []tapSink `json:"sinks"`
	MaxBufferedRxBytes uint32    `json:"max_buffered_rx_bytes"`
	MaxBufferedTxBytes uint32    `json:"max_buffered_tx_bytes"`
}

type tapSink struct {
	Format         string   `json:"format"`
	StreamingAdmin struct{} `json:"streaming_admin"`
}

// tapSession 建立一条 tap 管理流并读至中断/取消。返回中断原因（用于计数日志）。
func (s *Source) tapSession(ctx context.Context) error {
	pol := s.policy.Load()
	bodyLimit := s.cfg.MaxBodyBytes
	if pol.MaxBodySize < bodyLimit {
		bodyLimit = pol.MaxBodySize
	}
	post := tapPostBody{
		ConfigID: s.cfg.ConfigID,
		TapConfig: tapPostConfig{
			MatchConfig: tapMatchConfig{AnyMatch: true},
			OutputConfig: tapOutputConfig{
				Sinks: []tapSink{{Format: "JSON_BODY_AS_BYTES"}},
				// Envoy 侧正文缓冲上限随策略下发：超限由 Envoy 截断并置
				// truncated（截断后原始总大小不可确认 → body_quality 如实
				// truncated=true + original_total_size=null）
				MaxBufferedRxBytes: uint32(bodyLimit),
				MaxBufferedTxBytes: uint32(bodyLimit),
			},
		},
	}
	payload, err := json.Marshal(post)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+s.cfg.AdminAddr+"/tap", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 0, // 流式响应无总时限；生命周期由 ctx 控制
		Transport: &http.Transport{
			ResponseHeaderTimeout: s.cfg.ConnectTimeout,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /tap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.Stats.AdminRejects.Add(1)
		// 错误正文有界读取仅用于日志类别判断，不回显内容（可能含配置回显）
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("POST /tap 被拒绝: HTTP %d", resp.StatusCode)
	}
	sc := newFrameScanner(s.cfg.MaxMessageBytes)
	buf := make([]byte, 32<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			frames := sc.feed(buf[:n])
			for _, f := range frames {
				s.handleFrame(f)
			}
			if sc.overflowed() {
				s.Stats.OversizeDrops.Add(sc.takeOverflow())
			}
		}
		if rerr != nil {
			sc.reset() // 丢弃不完整半消息（有界：随缓冲区一并释放）
			if rerr == io.EOF {
				return errors.New("tap 流结束（对端关闭）")
			}
			return fmt.Errorf("tap 流读取: %w", rerr)
		}
	}
}

// handleFrame 处理一条完整 TraceWrapper JSON（解析失败只计数丢弃该条）。
func (s *Source) handleFrame(data []byte) {
	s.Stats.Received.Add(1)
	var tw traceWrapper
	if err := json.Unmarshal(data, &tw); err != nil {
		s.Stats.ParseErrors.Add(1)
		return
	}
	if tw.HTTPBufferedTrace == nil || tw.HTTPBufferedTrace.Request == nil {
		s.Stats.NonHTTPIgnored.Add(1)
		return
	}
	rec := s.normalize(tw.HTTPBufferedTrace, time.Now())
	if s.onRecord != nil {
		s.Stats.Emitted.Add(1)
		s.onRecord(rec)
	}
}

// frameScanner 美化 JSON 流分帧器（括号深度 + 字符串/转义状态机）。
// 非并发安全（每 channel 单协程使用）。
type frameScanner struct {
	max      int64
	buf      []byte
	depth    int
	inStr    bool
	esc      bool
	started  bool // 已进入一个顶层对象
	dropping bool // 当前帧已超限：字节不再累积（有界），状态机继续同步至闭合
	overflow int  // 超上限丢弃的帧数（待取）
}

func newFrameScanner(maxMessage int64) *frameScanner {
	return &frameScanner{max: maxMessage}
}

// feed 喂入一块字节，返回其中完整切出的帧（可能 0 或多条）。
// 分片/半消息：未闭合数据留存待续；单帧超 max：丢弃该帧字节但状态机
// 继续（保持深度/字符串状态），帧闭合后恢复计数。
func (sc *frameScanner) feed(chunk []byte) [][]byte {
	var out [][]byte
	frameStart := -1
	for i, b := range chunk {
		if sc.inStr {
			if sc.esc {
				sc.esc = false
			} else if b == '\\' {
				sc.esc = true
			} else if b == '"' {
				sc.inStr = false
			}
		} else {
			switch b {
			case '"':
				sc.inStr = true
			case '{':
				if sc.depth == 0 && !sc.started {
					sc.started = true
					frameStart = i
				}
				sc.depth++
			case '}':
				if sc.depth > 0 {
					sc.depth--
				}
				if sc.depth == 0 && sc.started {
					sc.started = false
					if !sc.dropping {
						var frame []byte
						if frameStart >= 0 {
							frame = append([]byte(nil), sc.buf...)
							frame = append(frame, chunk[frameStart:i+1]...)
						} else {
							frame = append([]byte(nil), sc.buf...)
							frame = append(frame, chunk[:i+1]...) // 跨块帧：前段在 buf
						}
						if int64(len(frame)) > sc.max {
							sc.overflow++
						} else {
							out = append(out, frame)
						}
					}
					sc.buf = sc.buf[:0]
					sc.dropping = false
					frameStart = -1
				}
			}
		}
	}
	if sc.started && !sc.dropping {
		// 留存未闭合部分；超上限则丢弃已缓存字节并进入 dropping
		// （状态机继续同步，本帧剩余字节不再累积——有界）
		if frameStart >= 0 {
			sc.buf = append(sc.buf, chunk[frameStart:]...)
		} else {
			sc.buf = append(sc.buf, chunk...)
		}
		if int64(len(sc.buf)) > sc.max {
			sc.overflow++
			sc.buf = sc.buf[:0]
			sc.dropping = true
		}
	}
	return out
}

// overflowed 是否有超限丢弃帧（供计数）。
func (sc *frameScanner) overflowed() bool { return sc.overflow > 0 }

// takeOverflow 取走并清零超限丢弃计数。
func (sc *frameScanner) takeOverflow() uint64 {
	n := sc.overflow
	sc.overflow = 0
	return uint64(n)
}

// reset 流中断时丢弃不完整半消息。
func (sc *frameScanner) reset() {
	sc.buf = sc.buf[:0]
	sc.depth = 0
	sc.inStr = false
	sc.esc = false
	sc.started = false
}
