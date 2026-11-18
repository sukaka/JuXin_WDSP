package pcapevidence

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ArtifactID 是RFC 4122 UUID，使用标准库实现以避免新增网关依赖。
type ArtifactID [16]byte

func NewArtifactID() (ArtifactID, error) {
	var id ArtifactID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

func ParseArtifactID(value string) (ArtifactID, error) {
	var id ArtifactID
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return id, fmt.Errorf("invalid evidence artifact UUID")
	}
	encoded := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36]
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(id) || copy(id[:], decoded) != len(id) {
		return ArtifactID{}, fmt.Errorf("invalid evidence artifact UUID")
	}
	return id, nil
}

func (id ArtifactID) String() string {
	encoded := hex.EncodeToString(id[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func (id ArtifactID) IsZero() bool {
	return id == ArtifactID{}
}

func (id ArtifactID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

func (id *ArtifactID) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	parsed, err := ParseArtifactID(value)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}
