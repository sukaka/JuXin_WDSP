// probe.go 零依赖隐私安全客户端防窃取探针（/_wdsp/cs/v1/probe.js）：
//   - 仅监控动态 <script> DOM 注入（MutationObserver）以及跨域 fetch / XMLHttpRequest / sendBeacon 目标 URL；
//   - 严禁读取任何表单值、密码、Cookie、Storage 或请求正文；
//   - 预计算 SHA-384 SRI 摘要常量，供敏感路径 HTML 响应注入带 integrity 属性的 <script defer> 标签。
package clientside

import (
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"strconv"
)

// ProbeScriptJS 嵌入式零依赖防窃取探针脚本（ES5 兼容，零外部依赖，绝不访问表单值/密码/Cookie）。
const ProbeScriptJS = `(function(){'use strict';if(window.__wdspCsProbe)return;window.__wdspCsProbe=1;var EP='/_wdsp/csp/v1/report',seen={},cnt=0,MAX=20,oBeacon=navigator.sendBeacon?navigator.sendBeacon.bind(navigator):null,oFetch=window.fetch?window.fetch.bind(window):null,oOpen=window.XMLHttpRequest&&XMLHttpRequest.prototype?XMLHttpRequest.prototype.open:null;function clean(u){try{var p=new URL(String(u),location.href);if(p.protocol==='http:'||p.protocol==='https:'||p.protocol==='ws:'||p.protocol==='wss:')return p.origin+p.pathname;return p.protocol}catch(_){return ''}}function isCross(u){try{var p=new URL(String(u),location.href);if(p.origin===location.origin)return false;return p.protocol==='http:'||p.protocol==='https:'||p.protocol==='ws:'||p.protocol==='wss:'}catch(_){return false}}function send(kind,target){try{if(cnt>=MAX)return;var t=clean(target),k=kind+'|'+t;if(!t||seen[k])return;seen[k]=1;cnt++;var body=JSON.stringify({type:'probe-alert',kind:kind,target:t,page:location.pathname});if(oBeacon){var b=new Blob([body],{type:'application/json'});if(oBeacon(EP,b))return}if(oFetch){oFetch(EP,{method:'POST',body:body,headers:{'Content-Type':'application/json'},keepalive:true,credentials:'omit'}).catch(function(){})}}catch(_){}}function checkScript(el){try{if(!el||el.tagName!=='SCRIPT')return;var s=el.getAttribute('src');if(s){var p=new URL(s,location.href);if(p.pathname==='/_wdsp/cs/v1/probe.js')return;send('dynamic_script',s)}else{send('dynamic_inline_script',location.pathname)}}catch(_){}}try{if(window.MutationObserver&&document.documentElement){new MutationObserver(function(ms){for(var i=0;i<ms.length;i++){var ns=ms[i].addedNodes;for(var j=0;j<ns.length;j++){var n=ns[j];if(!n||n.nodeType!==1)continue;if(n.tagName==='SCRIPT'){checkScript(n)}else if(n.querySelectorAll){var list=n.querySelectorAll('script');for(var k=0;k<list.length;k++)checkScript(list[k])}}}}).observe(document.documentElement,{childList:true,subtree:true})}}catch(_){}if(oFetch){window.fetch=function(req){try{var u=typeof req==='string'?req:(req&&typeof req.url==='string'?req.url:(req&&typeof req.href==='string'?req.href:''));if(u&&isCross(u))send('cross_origin_fetch',u)}catch(_){}return oFetch.apply(window,arguments)}}if(oOpen){XMLHttpRequest.prototype.open=function(m,u){try{if(typeof u!=='undefined'&&isCross(u))send('cross_origin_xhr',u)}catch(_){}return oOpen.apply(this,arguments)}}if(oBeacon){navigator.sendBeacon=function(u){try{if(typeof u!=='undefined'&&isCross(u))send('cross_origin_beacon',u)}catch(_){}return oBeacon.apply(navigator,arguments)}}})();`

// ProbeScriptSRI 探针脚本的 SHA-384 子资源完整性（SRI）预计算值。
// init 中通过真实 SHA-384 校验以确保与 ProbeScriptJS 字节恒定一致。
var ProbeScriptSRI = computeProbeSRI()

func computeProbeSRI() string {
	sum := sha512.Sum384([]byte(ProbeScriptJS))
	return "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
}

// ProbeScriptTag 返回注入到敏感路径 HTML 响应的 <script> 片段（带预计算 SHA-384 SRI 与 defer）。
func ProbeScriptTag() string {
	return `<script src="` + ProbeScriptPath + `" integrity="` + ProbeScriptSRI + `" defer></script>`
}

// ServeProbeScript 本地处理 GET/HEAD /_wdsp/cs/v1/probe.js（绝不反向代理）。
// 返回实际写出的 HTTP 状态码。
func ServeProbeScript(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("405 method not allowed"))
		return http.StatusMethodNotAllowed
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(ProbeScriptJS)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(ProbeScriptJS))
	}
	return http.StatusOK
}
