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
		"address":"http://localhost:8001",
		"public":"kFUFd29egtHp/jt17PyGm1RQp8cXFG3ADp3Dcd/vuhVfq0cOJYz2sZkM9EM3ZnZC",
		"signature":"hk3XmrO+XCT6hc51hQDaw1gLyxXyQTcIog/iTRTYZmBlgr7H5MvkXxNO0QiDb1mECjYFKV/+Qmw+GkoxoNbmpYn97HXt840VcRH7S9hcQMn63VOhDu8GwRaV/SLfQ9JV"
	},
	{
		"address":"http://localhost:8002",
		"public":"kjO7jmSZWj/GftWDZvjaC5W0m+03+eNlo9HWLutfc51B51A5Aofxo+kqYr4Ny3Bc",
		"signature":"hJnAukpvzUpesOvp3bhIfYqIDuEoJe3mj+HoJykCGcnmHp09BotZSOGjPMH//v8dGJVAkowbCayCFdW8fds/f8hHGodhmwjvMKmQAVrvYrmuiXAzmBH2FH1Y+uRp6sk2"
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
      	"address": "http://notthesameaddressaspublickey:8080",
		"public":"kFUFd29egtHp/jt17PyGm1RQp8cXFG3ADp3Dcd/vuhVfq0cOJYz2sZkM9EM3ZnZC",
		"signature":"hk3XmrO+XCT6hc51hQDaw1gLyxXyQTcIog/iTRTYZmBlgr7H5MvkXxNO0QiDb1mECjYFKV/+Qmw+GkoxoNbmpYn97HXt840VcRH7S9hcQMn63VOhDu8GwRaV/SLfQ9JV"
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
		"address":"http://localhost:8001",
		"public":"kFUFd29egtHp/jt17PyGm1RQp8cXFG3ADp3Dcd/vuhVfq0cOJYz2sZkM9EM3ZnZC",
		"signature":"notvalidrO+XCT6hc51hQDaw1gLyxXyQTcIog/iTRTYZmBlgr7H5MvkXxNO0QiDb1mECjYFKV/+Qmw+GkoxoNbmpYn97HXt840VcRH7S9hcQMn63VOhDu8GwRaV/SLfQ9JV"
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
		"address":"http://localhost:8001",
		"public":"kFUFd29egtHp/jt17PyGm1RQp8cXFG3ADp3Dcd/vuhVfq0cOJYz2sZkM9EM3ZnZC",
		"signature":"hk3XmrO+XCT6hc51hQDaw1gLyxXyQTcIog/iTRTYZmBlgr7H5MvkXxNO0QiDb1mECjYFKV/+Qmw+GkoxoNbmpYn97HXt840VcRH7S9hcQMn63VOhDu8GwRaV/SLfQ9JV"
	}
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
