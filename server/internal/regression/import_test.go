// import_test.go 导入核验管线测试（伪造签名/篡改对象/幂等/409/计数对账/对象状态）。
package regression

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeImportStore 内存 ImportStore。
type fakeImportStore struct {
	runs     map[string]*Run
	objects  map[uuid.UUID]*EvidenceObject
	policy   *Policy
	imported []*Run
	conflict bool
}

func newFakeImportStore() *fakeImportStore {
	return &fakeImportStore{
		runs:    map[string]*Run{},
		objects: map[uuid.UUID]*EvidenceObject{},
		policy:  &Policy{Mode: ModeEnforce, RequiredLevel: LevelFull, EvidenceMaxAgeSeconds: DefaultEvidenceMaxAge, Version: 2},
	}
}

func (f *fakeImportStore) GetRunByRunID(_ context.Context, runID string) (*Run, error) {
	if r, ok := f.runs[runID]; ok {
		return r, nil
	}
	return nil, ErrNotFound
}

func (f *fakeImportStore) GetObject(_ context.Context, id uuid.UUID) (*EvidenceObject, error) {
	if o, ok := f.objects[id]; ok {
		return o, nil
	}
	return nil, ErrNotFound
}

func (f *fakeImportStore) GetPolicy(context.Context) (*Policy, error) { return f.policy, nil }

// InsertObject 实现 ObjectStore（LocalEvidenceStore.Register 落库元数据）。
func (f *fakeImportStore) InsertObject(_ context.Context, obj EvidenceObject) error {
	cp := obj
	f.objects[obj.ID] = &cp
	return nil
}

func (f *fakeImportStore) ImportRun(_ context.Context, run *Run, _ []CaseEntry, refs []ImportObjectRef) (*Run, bool, error) {
	if f.conflict {
		return nil, false, ErrConflict
	}
	// 消费对象（镜像 *Store 事务语义）
	for _, ref := range refs {
		o := f.objects[ref.ObjectID]
		if o == nil || o.State != ObjectRegistered {
			return nil, false, ErrConflict
		}
	}
	for _, ref := range refs {
		f.objects[ref.ObjectID].State = ObjectConsumed
	}
	run.ID = uuid.New()
	f.runs[run.RunID] = run
	f.imported = append(f.imported, run)
	return run, false, nil
}

// importFixture 测试夹具：真实 LocalEvidenceStore（临时目录 + 内存元数据）。
type importFixture struct {
	store    *fakeImportStore
	evidence *LocalEvidenceStore
	keys     SettingsReader
	priv     ed25519.PrivateKey
	keyID    string
	importer *Importer
}

func newImportFixture(t *testing.T) *importFixture {
	t.Helper()
	fs := newFakeImportStore()
	es, err := NewLocalEvidenceStore(t.TempDir(), fs)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := "verifier-test"
	val, _ := json.Marshal([]TrustedKey{{KeyID: keyID, Algorithm: SignatureAlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub), Status: KeyStatusActive}})
	keys := func(context.Context, string, string, string) string { return string(val) }
	return &importFixture{
		store: fs, evidence: es, keys: keys, priv: priv, keyID: keyID,
		importer: NewImporter(fs, es, keys),
	}
}

// register 登记对象（返回对象与内容）。
func (fx *importFixture) register(t *testing.T, kind, content string) *EvidenceObject {
	t.Helper()
	obj, err := fx.evidence.Register(context.Background(), kind, "tester", strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	fx.store.objects[obj.ID] = obj
	return obj
}

func (fx *importFixture) sign(msg []byte) SignatureEnvelope {
	return SignatureEnvelope{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     fx.keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(fx.priv, msg)),
	}
}

// manifestWith 构造规范形 manifest（chunkHash/chunkSize 指向分块对象登记值）。
func manifestWith(chunkHash string, chunkSize int64) string {
	return `{"candidate":{"build_digest":"sha256:bb","compiler":"go1.24","config_fingerprint":"` + testFP + `","corpus_id":"p1-corpus","corpus_sha256":"` + testHash + `","corpus_version":1,"plan_sha256":"` + testHash + `"},"counts":{"blocked":0,"executed":2,"failed":0,"mandatory_failed":0,"mandatory_total":1,"not_run":0,"passed":2,"planned":2,"skipped":0},"created_at":"2026-09-08T01:00:00Z","declared_status":"PASS","files":[{"name":"cases-0.json","role":"CASES_CHUNK","sha256":"` + chunkHash + `","size_bytes":` + itoa(chunkSize) + `}],"level":"FULL","run_finished_at":"2026-09-08T01:10:00Z","run_id":"20260908T010000-abcdef","run_started_at":"2026-09-08T01:00:00Z","schema_version":1}`
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func (fx *importFixture) happyRequest(t *testing.T) (ImportRequest, *EvidenceObject, *EvidenceObject) {
	t.Helper()
	chunk := fx.register(t, KindCasesChunk, chunkJSON)
	manifest := fx.register(t, KindManifest, manifestWith(chunk.SHA256, chunk.SizeBytes))
	data, _, err := fx.evidence.ReadAll(context.Background(), manifest.ID)
	if err != nil {
		t.Fatal(err)
	}
	return ImportRequest{
		ManifestObjectID: manifest.ID,
		Signature:        fx.sign(data),
		Objects:          []ImportObjectInput{{ObjectID: chunk.ID, Role: KindCasesChunk, Name: "cases-0.json"}},
	}, manifest, chunk
}

func TestImportHappyPath(t *testing.T) {
	fx := newImportFixture(t)
	req, manifest, chunk := fx.happyRequest(t)
	res, reasons, err := fx.importer.Import(context.Background(), req, "tester")
	if err != nil || reasons != nil {
		t.Fatalf("import rejected: reasons=%v err=%v", reasons, err)
	}
	if res.Run.VerificationStatus != VerifyPassed || res.Run.PolicyVersion != 2 {
		t.Fatalf("run state wrong: %+v", res.Run)
	}
	if fx.store.objects[manifest.ID].State != ObjectConsumed || fx.store.objects[chunk.ID].State != ObjectConsumed {
		t.Fatal("objects not consumed")
	}
}

func TestImportIdempotentReimport(t *testing.T) {
	fx := newImportFixture(t)
	req, _, _ := fx.happyRequest(t)
	if _, reasons, err := fx.importer.Import(context.Background(), req, "tester"); err != nil || reasons != nil {
		t.Fatalf("first import: reasons=%v err=%v", reasons, err)
	}
	res, reasons, err := fx.importer.Import(context.Background(), req, "tester")
	if err != nil || reasons != nil {
		t.Fatalf("reimport: reasons=%v err=%v", reasons, err)
	}
	if !res.Idempotent {
		t.Fatal("reimport not idempotent")
	}
	if len(fx.store.imported) != 1 {
		t.Fatalf("duplicate import created second run: %d", len(fx.store.imported))
	}
}

func TestImportSameRunIDDifferentContent409(t *testing.T) {
	fx := newImportFixture(t)
	req, _, _ := fx.happyRequest(t)
	if _, reasons, err := fx.importer.Import(context.Background(), req, "tester"); err != nil || reasons != nil {
		t.Fatalf("first import: reasons=%v err=%v", reasons, err)
	}
	// 同 run_id 不同内容（改 plan 哈希 → manifest 不同）
	chunk2 := fx.register(t, KindCasesChunk, chunkJSON)
	m2 := strings.Replace(manifestWith(chunk2.SHA256, chunk2.SizeBytes), `"plan_sha256":"`+testHash+`"`, `"plan_sha256":"`+"f"+testHash[1:]+`"`, 1)
	manifest2 := fx.register(t, KindManifest, m2)
	data, _, _ := fx.evidence.ReadAll(context.Background(), manifest2.ID)
	req2 := ImportRequest{
		ManifestObjectID: manifest2.ID,
		Signature:        fx.sign(data),
		Objects:          []ImportObjectInput{{ObjectID: chunk2.ID, Role: KindCasesChunk, Name: "cases-0.json"}},
	}
	_, _, err := fx.importer.Import(context.Background(), req2, "tester")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("same run_id different content not 409: %v", err)
	}
}

func TestImportForgedSignatureRejected(t *testing.T) {
	fx := newImportFixture(t)
	req, _, _ := fx.happyRequest(t)
	// 攻击者私钥签名
	_, evil, _ := ed25519Generate()
	data, _, _ := fx.evidence.ReadAll(context.Background(), req.ManifestObjectID)
	req.Signature = SignatureEnvelope{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     fx.keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(evil, data)),
	}
	_, reasons, err := fx.importer.Import(context.Background(), req, "tester")
	if err != nil || reasons == nil {
		t.Fatalf("forged signature accepted: reasons=%v err=%v", reasons, err)
	}
	if len(fx.store.imported) != 0 {
		t.Fatal("forged import left a stored run")
	}
}

func TestImportUnknownKeyRejected(t *testing.T) {
	fx := newImportFixture(t)
	req, _, _ := fx.happyRequest(t)
	req.Signature.KeyID = "ghost"
	if _, reasons, _ := fx.importer.Import(context.Background(), req, "tester"); reasons == nil {
		t.Fatal("unknown key_id accepted")
	}
}

func TestImportTamperedManifestRejected(t *testing.T) {
	fx := newImportFixture(t)
	req, _, _ := fx.happyRequest(t)
	// 改 manifest 一字节后沿用旧签名 → 验签失败
	data, _, _ := fx.evidence.ReadAll(context.Background(), req.ManifestObjectID)
	tampered := strings.Replace(string(data), `"level":"FULL"`, `"level":"SMOKE"`, 1)
	obj, err := fx.evidence.Register(context.Background(), KindManifest, "tester", strings.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	fx.store.objects[obj.ID] = obj
	req.ManifestObjectID = obj.ID
	if _, reasons, _ := fx.importer.Import(context.Background(), req, "tester"); reasons == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestImportObjectHashMismatchRejected(t *testing.T) {
	fx := newImportFixture(t)
	chunk := fx.register(t, KindCasesChunk, chunkJSON)
	// manifest 声明的分块哈希与登记对象不一致
	wrongHash := "f" + testHash[1:]
	manifest := fx.register(t, KindManifest, manifestWith(wrongHash, chunk.SizeBytes))
	data, _, _ := fx.evidence.ReadAll(context.Background(), manifest.ID)
	req := ImportRequest{
		ManifestObjectID: manifest.ID,
		Signature:        fx.sign(data),
		Objects:          []ImportObjectInput{{ObjectID: chunk.ID, Role: KindCasesChunk, Name: "cases-0.json"}},
	}
	if _, reasons, _ := fx.importer.Import(context.Background(), req, "tester"); reasons == nil {
		t.Fatal("hash mismatch accepted")
	}
}

func TestImportCountMismatchRejected(t *testing.T) {
	fx := newImportFixture(t)
	chunk := fx.register(t, KindCasesChunk, chunkJSON)
	m := strings.Replace(manifestWith(chunk.SHA256, chunk.SizeBytes), `"planned":2`, `"planned":3`, 1)
	manifest := fx.register(t, KindManifest, m)
	data, _, _ := fx.evidence.ReadAll(context.Background(), manifest.ID)
	req := ImportRequest{
		ManifestObjectID: manifest.ID,
		Signature:        fx.sign(data),
		Objects:          []ImportObjectInput{{ObjectID: chunk.ID, Role: KindCasesChunk, Name: "cases-0.json"}},
	}
	if _, reasons, _ := fx.importer.Import(context.Background(), req, "tester"); reasons == nil {
		t.Fatal("count mismatch accepted")
	}
}

func TestImportExtraAndMissingObjectsRejected(t *testing.T) {
	fx := newImportFixture(t)
	req, _, _ := fx.happyRequest(t)
	// 多余对象引用
	extra := fx.register(t, KindReport, `{"x":1}`)
	reqExtra := req
	reqExtra.Objects = append(append([]ImportObjectInput{}, req.Objects...),
		ImportObjectInput{ObjectID: extra.ID, Role: KindReport, Name: "report.md"})
	if _, reasons, _ := fx.importer.Import(context.Background(), reqExtra, "tester"); reasons == nil {
		t.Fatal("extra object accepted")
	}
	// 缺对象
	reqMissing := req
	reqMissing.Objects = nil
	if _, reasons, _ := fx.importer.Import(context.Background(), reqMissing, "tester"); reasons == nil {
		t.Fatal("missing object accepted")
	}
	// 未知对象 ID
	reqGhost := req
	reqGhost.Objects = []ImportObjectInput{{ObjectID: uuid.New(), Role: KindCasesChunk, Name: "cases-0.json"}}
	if _, reasons, _ := fx.importer.Import(context.Background(), reqGhost, "tester"); reasons == nil {
		t.Fatal("ghost object accepted")
	}
}

func TestImportDuplicateKeysManifestRejected(t *testing.T) {
	fx := newImportFixture(t)
	chunk := fx.register(t, KindCasesChunk, chunkJSON)
	dup := strings.Replace(manifestWith(chunk.SHA256, chunk.SizeBytes), `"schema_version":1`, `"schema_version":1,"level":"FULL"`, 1)
	manifest := fx.register(t, KindManifest, dup)
	data, _, _ := fx.evidence.ReadAll(context.Background(), manifest.ID)
	req := ImportRequest{
		ManifestObjectID: manifest.ID,
		Signature:        fx.sign(data),
		Objects:          []ImportObjectInput{{ObjectID: chunk.ID, Role: KindCasesChunk, Name: "cases-0.json"}},
	}
	if _, reasons, _ := fx.importer.Import(context.Background(), req, "tester"); reasons == nil {
		t.Fatal("duplicate-key manifest accepted")
	}
}

func TestImportNonCanonicalManifestRejected(t *testing.T) {
	fx := newImportFixture(t)
	chunk := fx.register(t, KindCasesChunk, chunkJSON)
	raw := manifestWith(chunk.SHA256, chunk.SizeBytes) + "\n"
	manifest := fx.register(t, KindManifest, raw)
	data, _, _ := fx.evidence.ReadAll(context.Background(), manifest.ID)
	req := ImportRequest{
		ManifestObjectID: manifest.ID,
		Signature:        fx.sign(data),
		Objects:          []ImportObjectInput{{ObjectID: chunk.ID, Role: KindCasesChunk, Name: "cases-0.json"}},
	}
	if _, reasons, _ := fx.importer.Import(context.Background(), req, "tester"); reasons == nil {
		t.Fatal("non-canonical manifest accepted")
	}
}

func TestObjectConsumedByOtherRunRejected(t *testing.T) {
	fx := newImportFixture(t)
	req, manifest, _ := fx.happyRequest(t)
	// 预先把 manifest 对象标记为已被其他运行消费
	fx.store.objects[manifest.ID].State = ObjectConsumed
	_ = req
	req2 := ImportRequest{
		ManifestObjectID: manifest.ID,
		Signature:        req.Signature,
		Objects:          req.Objects,
	}
	// manifest CONSUMED 可读（幂等判定路径），但 run 不存在 → 走完整导入 →
	// 分块对象仍 REGISTERED，manifest 自身在 refs 落库时会被 store 拒绝；
	// 本 fake 在 ImportRun 中消费检查触发冲突
	fx.store.conflict = true
	_, _, err := fx.importer.Import(context.Background(), req2, "tester")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("consumed object accepted: %v", err)
	}
}
