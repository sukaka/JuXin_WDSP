package upgrades

import (
	"bytes"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
)

func TestArchiveManifestCandidatesHaveAggregateMemoryBound(t *testing.T) {
	for _, layout := range []string{"nested", "mixed-roots", "duplicate", "normalized-duplicate"} {
		t.Run(layout, func(t *testing.T) {
			payload := make([]byte, maxArtifactManifestBytes)
			var entries []testArchiveEntry
			for i := 0; i < 8; i++ {
				name := fmt.Sprintf("pkg/nested%d/manifest.json", i)
				switch layout {
				case "mixed-roots":
					name = fmt.Sprintf("pkg%d/manifest.json", i)
				case "duplicate":
					name = "pkg/manifest.json"
				case "normalized-duplicate":
					name = "pkg/" + string(bytes.Repeat([]byte("/"), i)) + "manifest.json"
				}
				entries = append(entries, testArchiveEntry{name: name, data: payload})
			}
			archive := writeTestArchive(t, filepath.Join(t.TempDir(), "probe.tar.gz"), entries)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := scanPackageArchiveReader(bytes.NewReader(archive))
			runtime.ReadMemStats(&after)
			if (layout == "duplicate" || layout == "normalized-duplicate") && err == nil {
				t.Fatal("重复归一化路径必须拒绝")
			}
			// 64 MiB 解压输入不应被清单候选完整缓冲；保留运行时分配余量。
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 24<<20 {
				t.Fatalf("扫描分配 %d 字节，超过 24 MiB；err=%v", allocated, err)
			}
		})
	}
}

func TestArchiveStreamsNestedManifestPayload(t *testing.T) {
	for _, prefix := range []string{"", "release/"} {
		t.Run(prefix, func(t *testing.T) {
			// basename 与保留清单相同的普通文件不受元数据大小限制。
			payload := bytes.Repeat([]byte("x"), int(maxArtifactManifestBytes)+1)
			files := map[string][]byte{"payload/manifest.json": payload, "payload/manifest.sig": payload}
			manifest := testManifest(t, "2.1.0", files)
			archive := writeTestArchive(t, filepath.Join(t.TempDir(), "nested.tar.gz"), []testArchiveEntry{
				{name: prefix + "manifest.json", data: manifest},
				{name: prefix + "payload/manifest.json", data: payload},
				{name: prefix + "payload/manifest.sig", data: payload},
			})
			scan, err := scanPackageArchiveReader(bytes.NewReader(archive))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(scan.manifestBytes, manifest) || len(scan.files) != 2 {
				t.Fatal("根级元数据与同名普通文件必须分开处理")
			}
		})
	}
}
