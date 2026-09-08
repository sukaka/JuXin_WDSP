package botchallenge

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
)

// render.go 挑战页渲染（任务书 §5.1/§5.3/§6）：
//   - CSP nonce（每响应 crypto/rand）、仅第一方脚本/连接（script-src 'nonce-*'、
//     connect-src 'self'）、禁止嵌入（frame-ancestors 'none' + X-Frame-Options DENY）；
//   - Cache-Control: no-store（不经 CDN 共享缓存）；
//   - 所有动态文本转义（RequestID 经 html.EscapeString；题目参数经 json.Marshal
//     默认 HTML 转义——<>& 以 \uXXXX 形式输出，不可能闭合 script 元素）；无 eval；
//   - JS 可中止（取消按钮）、定期让出主线程（分片 + setTimeout(0)）、单次计算
//     预算 ≤2s（超时显示手动重试说明，不无限加难度）；
//   - 最多自动刷新一次（sessionStorage 一次性标记；仍被挑战则显示可恢复原因，
//     避免无限循环）；成功只刷新当前 URL，不读任意跳转地址、不重放 POST；
//   - JS 内嵌 SHA-256 自检（空串摘要比对 FIPS 180-4 已知向量，不兼容则明示）。
//
// 页面为纯本地静态资产 + 第一方 fetch（verify 同源 POST），不接任何外部服务。

// challengePageParams 题目参数（下发页面；nonce/difficulty 是题目参数而非秘密——
// 权威判定在服务端状态）。
type challengePageParams struct {
	ChallengeID string
	Nonce       string
	Difficulty  int
	AppID       string
	Host        string // 规范化 Host（PoW 输入材料；与 verify 时服务端 normalizeHost(r.Host) 一致）
	VerifyPath  string
	BudgetMS    int
	RequestID   string
}

// paramsJSON 参数 JSON 线格式（json tag 为页面契约）。
type paramsJSON struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	Difficulty  int    `json:"difficulty"`
	AppID       string `json:"app"`
	Host        string `json:"host"`
	VerifyPath  string `json:"verify_path"`
	BudgetMS    int    `json:"budget_ms"`
}

// renderChallenge 写 403 挑战页（会话 Cookie 由 Offer 先行 Set-Cookie）。
func (s *Service) renderChallenge(w http.ResponseWriter, r *http.Request, p challengePageParams, cspNonce string) {
	pj, err := json.Marshal(paramsJSON{
		ChallengeID: p.ChallengeID,
		Nonce:       p.Nonce,
		Difficulty:  p.Difficulty,
		AppID:       p.AppID,
		Host:        p.Host,
		VerifyPath:  p.VerifyPath,
		BudgetMS:    p.BudgetMS,
	})
	if err != nil {
		// 静态结构序列化不可失败；防御性兜底
		writeStatusPage(w, http.StatusServiceUnavailable, retryAfterUnavailable, "服务暂不可用", "安全验证服务暂时不可用，请稍后重试。", p.RequestID)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+cspNonce+"'; style-src 'nonce-"+cspNonce+
			"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusForbidden)
	writeChallengeHTML(w, string(pj), cspNonce, p.RequestID)
}

// writeChallengeErrorHTML 静态错误页（429/503 签发失败用；全部动态文本转义）。
func writeChallengeErrorHTML(w http.ResponseWriter, title, msg, requestID string) {
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<title>%s</title></head><body><main>`+
		`<h1>%s</h1><p>%s</p><p>请求编号：%s</p>`+
		`</main></body></html>`,
		html.EscapeString(title), html.EscapeString(title), html.EscapeString(msg), html.EscapeString(requestID))
}

// writeChallengeHTML 挑战页（CSP nonce 挂脚本/样式；参数块为 application/json
// 非执行脚本；JS 求解器为静态常量）。
func writeChallengeHTML(w http.ResponseWriter, pj, cspNonce, requestID string) {
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<title>安全验证</title>`+
		`<style nonce="%s">%s</style></head><body><main>`+
		`<h1>安全验证</h1>`+
		`<p id="wdsp-status" role="status" aria-live="polite">正在完成安全验证，请稍候…</p>`+
		`<noscript><p>此安全验证需要启用 JavaScript。请在浏览器中启用 JavaScript 后刷新页面重试。</p></noscript>`+
		`<div id="wdsp-manual" hidden><p id="wdsp-reason"></p>`+
		`<button id="wdsp-retry" type="button">重试</button> `+
		`<button id="wdsp-cancel" type="button" hidden>取消</button></div>`+
		`<p>请求编号：%s</p>`+
		`</main>`+
		`<script nonce="%s" id="wdsp-bot-params" type="application/json">%s</script>`+
		`<script nonce="%s">%s</script>`+
		`</body></html>`,
		html.EscapeString(cspNonce), challengeCSS,
		html.EscapeString(requestID),
		html.EscapeString(cspNonce), pj,
		html.EscapeString(cspNonce), challengeJS)
}

// challengeCSS 极简样式（静态常量；无外部资源）。
const challengeCSS = `body{font-family:system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em;line-height:1.6;color:#222}` +
	`button{font-size:1em;padding:.4em 1.2em;cursor:pointer}`

// challengeJS 受限本地求解器（静态常量；无 eval、无外部引用、不读业务数据）：
// 分片计算 + setTimeout(0) 让出主线程；budget_ms 预算超时转手动重试；
// 成功 POST 同源 verify，204 后最多自动刷新一次（sessionStorage 标记）。
// SHA-256 为 FIPS 180-4 标准实现（启动自检空串向量，不兼容则明示失败）。
const challengeJS = `(function(){
"use strict";
var paramsEl=document.getElementById("wdsp-bot-params");
if(!paramsEl){return}
var params=JSON.parse(paramsEl.textContent);
var statusEl=document.getElementById("wdsp-status");
var manualEl=document.getElementById("wdsp-manual");
var reasonEl=document.getElementById("wdsp-reason");
var retryBtn=document.getElementById("wdsp-retry");
var cancelBtn=document.getElementById("wdsp-cancel");
var errText={BODY_INVALID:"请求格式异常，请刷新页面重试。",ORIGIN_REQUIRED:"当前浏览器缺少必要的来源标识，请更换浏览器或刷新重试。",ORIGIN_MISMATCH:"请求来源校验未通过。",FETCH_METADATA_REJECTED:"请求来源校验未通过。",SESSION_INVALID:"验证会话已失效，正在重新加载…",RATE_LIMITED:"操作过于频繁，请稍后重试。",CHALLENGE_NOT_FOUND:"验证已失效，请刷新页面重试。",CHALLENGE_EXPIRED:"验证已过期，请刷新页面重试。",BINDING_MISMATCH:"验证上下文不一致，请刷新页面重试。",BAD_SOLUTION:"计算结果未通过校验。",ATTEMPTS_EXHAUSTED:"验证次数已用尽，请刷新页面重试。",STATE_UNAVAILABLE:"验证服务暂时不可用，请稍后重试。"};
function setStatus(t){if(statusEl){statusEl.textContent=t}}
function showManual(t){setStatus("需要手动操作");if(reasonEl){reasonEl.textContent=t}if(manualEl){manualEl.hidden=false}if(cancelBtn){cancelBtn.hidden=true}if(retryBtn){retryBtn.focus()}}
function ascii(s){var b=new Uint8Array(s.length);for(var i=0;i<s.length;i++){b[i]=s.charCodeAt(i)&255}return b}
function hexToBytes(h){var b=new Uint8Array(h.length/2);for(var i=0;i<b.length;i++){b[i]=parseInt(h.substr(i*2,2),16)}return b}
function lp(b){var o=new Uint8Array(b.length+4);var n=b.length;o[0]=(n>>>24)&255;o[1]=(n>>>16)&255;o[2]=(n>>>8)&255;o[3]=n&255;o.set(b,4);return o}
function concat(parts){var n=0;for(var i=0;i<parts.length;i++){n+=parts[i].length}var o=new Uint8Array(n);var p=0;for(var j=0;j<parts.length;j++){o.set(parts[j],p);p+=parts[j].length}return o}
function sha256(msg){
var K=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];
var H=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225];
var l=msg.length;
var withPad=l+9+((55-l)%64+64)%64;
var b=new Uint8Array(withPad);b.set(msg);b[l]=128;
var bitLen=l*8;
b[withPad-4]=Math.floor(bitLen/16777216)&255;b[withPad-3]=(bitLen>>>16)&255;b[withPad-2]=(bitLen>>>8)&255;b[withPad-1]=bitLen&255;
var w=new Uint32Array(64);
function rr(x,n){return(x>>>n)|(x<<(32-n))}
for(var off=0;off<withPad;off+=64){
for(var t=0;t<16;t++){w[t]=(b[off+t*4]<<24)|(b[off+t*4+1]<<16)|(b[off+t*4+2]<<8)|b[off+t*4+3]}
for(var t2=16;t2<64;t2++){var s0=rr(w[t2-15],7)^rr(w[t2-15],18)^(w[t2-15]>>>3);var s1=rr(w[t2-2],17)^rr(w[t2-2],19)^(w[t2-2]>>>10);w[t2]=(w[t2-16]+s0+w[t2-7]+s1)|0}
var a=H[0],bb=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],hh=H[7];
for(var t3=0;t3<64;t3++){var S1=rr(e,6)^rr(e,11)^rr(e,25);var ch=(e&f)^(~e&g);var t1=(hh+S1+ch+K[t3]+w[t3])|0;var S0=rr(a,2)^rr(a,13)^rr(a,22);var mj=(a&bb)^(a&c)^(bb&c);var t2v=(S0+mj)|0;hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=bb;bb=a;a=(t1+t2v)|0}
H[0]=(H[0]+a)|0;H[1]=(H[1]+bb)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+hh)|0}
var out=new Uint8Array(32);
for(var i2=0;i2<8;i2++){out[i2*4]=(H[i2]>>>24)&255;out[i2*4+1]=(H[i2]>>>16)&255;out[i2*4+2]=(H[i2]>>>8)&255;out[i2*4+3]=H[i2]&255}
return out}
function hexOf(b){var s="";for(var i=0;i<b.length;i++){s+=(b[i]<16?"0":"")+b[i].toString(16)}return s}
function leadingZeroBits(d){var n=0;for(var i=0;i<d.length;i++){var x=d[i];if(x===0){n+=8;continue}for(var k=7;k>=0;k--){if(x&(1<<k)){return n}n++}}return n}
var prefix=concat([ascii("wdsp-bot-pow-v1"),lp(hexToBytes(params.challenge_id)),lp(hexToBytes(params.nonce)),lp(ascii(params.app)),lp(ascii(params.host))]);
function preimage(sol){return concat([prefix,lp(ascii(sol))])}
function reloadOnce(){try{if(sessionStorage.getItem("wdsp.bot.rl")==="1"){showManual("验证已通过，请手动刷新本页面继续访问。");return}sessionStorage.setItem("wdsp.bot.rl","1")}catch(e){}
location.reload()}
var aborted=false,solving=false;
function submit(sol){setStatus("正在提交验证…");
fetch(params.verify_path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({challenge_id:params.challenge_id,solution:sol})}).then(function(resp){
if(resp.status===204){reloadOnce();return}
resp.json().then(function(body){var code=body&&body.error?body.error:"";showManual(errText[code]||"验证未通过（"+resp.status+"），请稍后重试。")},function(){showManual("验证未通过（"+resp.status+"），请稍后重试。")})},function(){showManual("网络异常，请检查连接后重试。")})}
function solve(){if(solving){return}solving=true;aborted=false;if(manualEl){manualEl.hidden=true}if(cancelBtn){cancelBtn.hidden=false}
setStatus("正在完成安全验证，请稍候…");
var start=Date.now();var i=0;var chunk=2048;var budget=params.budget_ms>0?params.budget_ms:2000;
function step(){if(aborted){solving=false;return}
var end=i+chunk;
for(;i<end;i++){var d=sha256(preimage(String(i)));if(leadingZeroBits(d)>=params.difficulty){solving=false;submit(String(i));return}}
if(Date.now()-start>budget){solving=false;showManual("计算超时：您的设备未能在时限内完成验证计算。请点击重试，或刷新页面重新开始。");return}
setTimeout(step,0)}
step()}
if(hexOf(sha256(new Uint8Array(0)))!=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"){showManual("当前浏览器的安全计算组件不兼容，请更换浏览器重试。");return}
if(retryBtn){retryBtn.addEventListener("click",function(){solve()})}
if(cancelBtn){cancelBtn.addEventListener("click",function(){aborted=true;showManual("已取消验证计算。点击重试可重新开始。")})}
solve()})();
`
