package encoding

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// UnpaddedBytes is a wrapper type that ensures bytes are marshalled to base64
// in json with padding characters
type UnpaddedBytes []byte

func (b *UnpaddedBytes) MarshalJSON() ([]byte, error) {
	encoded := base64.RawStdEncoding.EncodeToString(*b)
	return json.Marshal(encoded)
}

func (b *UnpaddedBytes) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}

	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

// HexBytes is a wrapper type that ensures bytes are marshalled to
// hex in json
type HexBytes []byte

func (b HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%s", hex.EncodeToString(b)))
}

func (b *HexBytes) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}

	decoded, err := hex.DecodeString(strings.TrimLeft(encoded, "0x"))
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}
