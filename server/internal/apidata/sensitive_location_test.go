package apidata

import "testing"

func TestValidateTypeAcceptsFileLocation(t *testing.T) {
	dataType := SensitiveDataType{
		Name: "导出手机号", DataType: "phone", Level: LevelSensitive,
		Status: TypeStatusEnabled, Regex: `^1[3-9]\d{9}$`, Locations: []string{"file"},
	}
	if err := validateType(&dataType); err != nil {
		t.Fatalf("file location should be accepted: %v", err)
	}
}

func TestCreateTypeWithFileLocationHTTP(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))
	req := validTypeReq()
	req["locations"] = []string{"file"}
	req["regex"] = `^1[3-9]\d{9}$`
	created := createType(t, mux, req)
	if len(created.Locations) != 1 || created.Locations[0] != "file" {
		t.Fatalf("file location must survive the management API: %+v", created.Locations)
	}
}
