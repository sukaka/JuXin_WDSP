package apidataflow

import (
	"testing"

	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

func TestClassifyObservationHTTP(t *testing.T) {
	filter := apiassets.DefaultDiscoveryFilterConfig()

	t.Run("静态资源与 HTML 页面应被过滤", func(t *testing.T) {
		cases := []agents.APIObservationEnvelope{
			{
				APIObservationRecord: agents.APIObservationRecord{
					HTTP: agents.APIObservationHTTP{
						Direction: "SERVER", Method: "GET", PathTemplate: "/astro/page.BsuiZEAU.js",
						ResponseContentType: "application/javascript", Status: 200,
					},
				},
			},
			{
				APIObservationRecord: agents.APIObservationRecord{
					HTTP: agents.APIObservationHTTP{
						Direction: "SERVER", Method: "GET", PathTemplate: "/favicon_128x128.ico",
						ResponseContentType: "image/x-icon", Status: 200,
					},
				},
			},
			{
				APIObservationRecord: agents.APIObservationRecord{
					HTTP: agents.APIObservationHTTP{
						Direction: "SERVER", Method: "GET", PathTemplate: "/downloads/pkg.tar.gz",
						ResponseContentType: "application/gzip", Status: 200,
					},
				},
			},
			{
				APIObservationRecord: agents.APIObservationRecord{
					HTTP: agents.APIObservationHTTP{
						Direction: "SERVER", Method: "GET", PathTemplate: "/products",
						ResponseContentType: "text/html; charset=utf-8", Status: 200,
					},
				},
			},
		}
		for _, rec := range cases {
			cls, proto := classifyObservationHTTP(rec)
			if filtered, _ := filter.ShouldFilterDiscovery(rec.HTTP.Method, rec.HTTP.PathTemplate, cls.IsAPI); !filtered {
				t.Fatalf("expected %s %s (proto=%s cls=%+v) to be filtered", rec.HTTP.Method, rec.HTTP.PathTemplate, proto, cls)
			}
		}
	})

	t.Run("JSON REST 与进程内框架写接口保留为 API", func(t *testing.T) {
		jsonRec := agents.APIObservationEnvelope{
			APIObservationRecord: agents.APIObservationRecord{
				HTTP: agents.APIObservationHTTP{
					Direction: "SERVER", Method: "GET", PathTemplate: "/orders/list",
					ResponseContentType: "application/json", Status: 200,
				},
			},
		}
		cls, proto := classifyObservationHTTP(jsonRec)
		if !cls.IsAPI || proto != "REST_JSON" {
			t.Fatalf("GET JSON observation should be REST_JSON API: cls=%+v proto=%q", cls, proto)
		}
		if filtered, reason := filter.ShouldFilterDiscovery(jsonRec.HTTP.Method, jsonRec.HTTP.PathTemplate, cls.IsAPI); filtered {
			t.Fatalf("GET JSON observation should not be filtered: %s", reason)
		}

		fwRec := agents.APIObservationEnvelope{
			APIObservationRecord: agents.APIObservationRecord{
				HTTP: agents.APIObservationHTTP{
					Direction: "SERVER", Method: "POST", PathTemplate: "/internal/orders/{id}/submit",
					Status: 204,
				},
				Quality: agents.APIObservationQuality{RouteSource: "FRAMEWORK"},
			},
		}
		cls2, _ := classifyObservationHTTP(fwRec)
		if !cls2.IsAPI {
			t.Fatalf("framework POST route should remain API: %+v", cls2)
		}
	})
}
