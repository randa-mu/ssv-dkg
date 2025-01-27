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
  "public": "kNe77jLEBddtf3Xdnzo0YBwovjHemgpN/enBPBNh/yjcozshAoAPlXB7ttkF+4fu",
  "signature": "s9LiL2q1iqsNC2oWyM9mz8mrTnAAtHVv19BaXZXa1NSc1DGSfZjPpp686okVlrdyBMmnQgzYMegpuFgKZ2ZEDDj6Nw9ubrNQioGWOFtndbMUHQfQ82DTXTsb5hz0MJFX"
}, {
  "operator_id": 3,
  "address": "http://127.0.0.1:8083",
  "public": "qa49KGl9moW+GEHol+9lVZmniwKoeSgVTh6FAXQsENlIS8WTRWgO6mSfRXGUwo7D",
  "signature": "gx7XWG4cc7gzPj/qB0rqNzzqChaOgrByxQ+bNJeHMRkBm1jyvcvmrWQGbOE4fzZID85edxt+4B1V1zctG75OL+7MOA2RKK8EAm44i7RCWsBwvXYOwDOc39yCtx9cdgwz"
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
  "operator_id": 3,
  "address": "differentaddresstokey.com",,
  "public": "qa49KGl9moW+GEHol+9lVZmniwKoeSgVTh6FAXQsENlIS8WTRWgO6mSfRXGUwo7D",
  "signature": "gx7XWG4cc7gzPj/qB0rqNzzqChaOgrByxQ+bNJeHMRkBm1jyvcvmrWQGbOE4fzZID85edxt+4B1V1zctG75OL+7MOA2RKK8EAm44i7RCWsBwvXYOwDOc39yCtx9cdgwz"
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
  			"address": "http://127.0.0.1:8083",
  			"public": "qa49KGl9moW+GEHol+9lVZmniwKoeSgVTh6FAXQsENlIS8WTRWgO6mSfRXGUwo7D",
  			"signature": "gx7XWG4cc7gzPj/qB0rqNzzqChaOgrByxQ+bNJeHMRkBm1jyvcvmrWQGbOE4fzZID85edxt+4B1V1zctG75OL+7MOA2RKK8EAm44i7RCWsBwvXYOwDOc39yCtx9cdgwz"
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
  "operator_id": 3,
  "address": "http://127.0.0.1:8083",
  "public": "qa49KGl9moW+GEHol+9lVZmniwKoeSgVTh6FAXQsENlIS8WTRWgO6mSfRXGUwo7D",
  "signature": "notvalidcc7gzPj/qB0rqNzzqChaOgrByxQ+bNJeHMRkBm1jyvcvmrWQGbOE4fzZID85edxt+4B1V1zctG75OL+7MOA2RKK8EAm44i7RCWsBwvXYOwDOc39yCtx9cdgwz"
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
