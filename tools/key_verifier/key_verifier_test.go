package key_verifier

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidKeyValidates(t *testing.T) {
	t.Parallel()

	valid := `
{
  "operators": [
    {
      "operator_id": 4,
      "address": "http://127.0.0.1:8084",
      "public": "kvlh/8NwkDszMLYKZ2NZfPUbTETUQATZjkVVJgsyDRfmPsG1ANeSpup0qBQmQeBg",
      "signature": "iZMqMYRQ3p8pn3kyfatE4XKwzOOkBTKjbU1hn/5bXJn191Iny0m08lSfe4LRsWhvBvdwlYYt5imem2NVaNmoBLY3ydTl3EyXQS7GtF0aCMk+tkj6I94vbOx8YeHPdd59"
    },
	{
      "operator_id": 3,
      "address": "http://127.0.0.1:8083",
      "public": "tEGKf8Lm3pRPrOCNBRtQJBkRybNenn7vmAOJvOCiCODxp86nwILFTYQRl3xk5tum",
      "signature": "pdUnns3/Au56zgUTdoiFYX4YW7i8WK83yrzw13ZkHCY3Wquy5psLkwmRyB2K/9DfFJj9HOy8FQ0ojM1SCoKv6k/++XlYLSGQMYpeVmiRjvwIYvhMMSUEF1rbcubYz6fE"
	}
  ]
}`

	p := path.Join(t.TempDir(), "keys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}

	require.NoError(t, VerifyKeys(p))
}

func TestInvalidAddressReturnsError(t *testing.T) {
	t.Parallel()

	invalid := `
{
  "operators": [
    {
      "operator_id": 4,
      address": "http://notthesameaddressaspublickey:8080",
      "public": "kvlh/8NwkDszMLYKZ2NZfPUbTETUQATZjkVVJgsyDRfmPsG1ANeSpup0qBQmQeBg",
      "signature": "iZMqMYRQ3p8pn3kyfatE4XKwzOOkBTKjbU1hn/5bXJn191Iny0m08lSfe4LRsWhvBvdwlYYt5imem2NVaNmoBLY3ydTl3EyXQS7GtF0aCMk+tkj6I94vbOx8YeHPdd59"
    }
  ]
}`

	p := path.Join(t.TempDir(), "keys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(invalid))
	if err != nil {
		t.Fatal(err)
	}

	require.Error(t, VerifyKeys(p))
}

func TestMissingOperatorIDReturnsError(t *testing.T) {
	t.Parallel()

	invalid := `
    {
      "operators": [
        {
          "address": "http://127.0.0.1:8084",
          "public": "kvlh/8NwkDszMLYKZ2NZfPUbTETUQATZjkVVJgsyDRfmPsG1ANeSpup0qBQmQeBg",
          "signature": "iZMqMYRQ3p8pn3kyfatE4XKwzOOkBTKjbU1hn/5bXJn191Iny0m08lSfe4LRsWhvBvdwlYYt5imem2NVaNmoBLY3ydTl3EyXQS7GtF0aCMk+tkj6I94vbOx8YeHPdd59"
        }
      ]
    }`

	p := path.Join(t.TempDir(), "keys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(invalid))
	if err != nil {
		t.Fatal(err)
	}

	require.Error(t, VerifyKeys(p))
}

func TestInvalidSignatureReturnsError(t *testing.T) {
	t.Parallel()

	invalid := `
{
  "operators": [
    {
      "operator_id": 4,
      "address": "http://127.0.0.1:8084",
      "public": "kvlh/8NwkDszMLYKZ2NZfPUbTETUQATZjkVVJgsyDRfmPsG1ANeSpup0qBQmQeBg",
      "signature": "notvalidRQ3p8pn3kyfatE4XKwzOOkBTKjbU1hn/5bXJn191Iny0m08lSfe4LRsWhvBvdwlYYt5imem2NVaNmoBLY3ydTl3EyXQS7GtF0aCMk+tkj6I94vbOx8YeHPdd59"
    }
  ]
}`

	p := path.Join(t.TempDir(), "keys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(invalid))
	if err != nil {
		t.Fatal(err)
	}

	require.Error(t, VerifyKeys(p))
}

func TestInvalidJsonReturnsError(t *testing.T) {
	t.Parallel()

	// missing closing [
	invalid := `
{
  "operators": [
    {
      "operator_id": 4,
      "address": "http://127.0.0.1:8084",
      "public": "kvlh/8NwkDszMLYKZ2NZfPUbTETUQATZjkVVJgsyDRfmPsG1ANeSpup0qBQmQeBg",
      "signature": "iZMqMYRQ3p8pn3kyfatE4XKwzOOkBTKjbU1hn/5bXJn191Iny0m08lSfe4LRsWhvBvdwlYYt5imem2NVaNmoBLY3ydTl3EyXQS7GtF0aCMk+tkj6I94vbOx8YeHPdd59"
    },
}`

	p := path.Join(t.TempDir(), "keys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(invalid))
	if err != nil {
		t.Fatal(err)
	}

	require.Error(t, VerifyKeys(p))
}

func TestNonExistentFileReturnsError(t *testing.T) {
	t.Parallel()

	require.Error(t, VerifyKeys("somenonsensepath"))
}
