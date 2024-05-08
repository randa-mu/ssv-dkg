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
      "validator_nonce": 1,
      "address": "http://127.0.0.1:8081",
      "public": "ho/OAKsG0JfQCnshVS2jgn8ANXxyCGshck9fyosN8ANwmt3MRWgx2gNfWLoon7uG",
      "signature": "h0uH2JhtqpbiwejHCbJAN9ppJBEqE+jF7DLWdBLNrCYMfzwserj2i5SK3W35CNhkF+GcHb6e3JwLzfkY7vicI7ZrsPMU9fNJ7YXl0sd7pbhyHsyhY9f5XswyrbmxR1Rw"
    },
    {
      "validator_nonce": 2,
      "address": "http://127.0.0.1:8082",
      "public": "q2blC6iQjSfit5mrg0DOn/EZAi2DaK4v76Zu/mO/6Eyy6S9fCnNKEdOS/WEpLB2a",
      "signature": "gsnlb5DmA0TMrzodm1L/QpSm/UV6GTXy9MX62GVUoyyF8sEAkP+RuP8kwcG7k5s+GDZbIR+ZBLaPCOY5cERjmJUvqyXY0fx0ytqwgLmM7vK9xLdNEDC/7ccM0ovl1A0c"
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

func TestMissingValidatorNonceFails(t *testing.T) {
	t.Parallel()

	invalid := `
{
  "operators": [
    {
		"address":"http://127.0.0.1:8081",
		"public":"ho/OAKsG0JfQCnshVS2jgn8ANXxyCGshck9fyosN8ANwmt3MRWgx2gNfWLoon7uG",
        "signature": "h0uH2JhtqpbiwejHCbJAN9ppJBEqE+jF7DLWdBLNrCYMfzwserj2i5SK3W35CNhkF+GcHb6e3JwLzfkY7vicI7ZrsPMU9fNJ7YXl0sd7pbhyHsyhY9f5XswyrbmxR1Rw"
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

func TestInvalidAddressReturnsError(t *testing.T) {
	t.Parallel()

	invalid := `
{
  "operators": [
    {
		"validator_nonce":1,
      	"address": "http://notthesameaddressaspublickey:8080",
		"public":"ho/OAKsG0JfQCnshVS2jgn8ANXxyCGshck9fyosN8ANwmt3MRWgx2gNfWLoon7uG",
        "signature": "h0uH2JhtqpbiwejHCbJAN9ppJBEqE+jF7DLWdBLNrCYMfzwserj2i5SK3W35CNhkF+GcHb6e3JwLzfkY7vicI7ZrsPMU9fNJ7YXl0sd7pbhyHsyhY9f5XswyrbmxR1Rw"
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
		"validator_nonce":1,
		"address":"http://127.0.0.1:8081",
		"public":"ho/OAKsG0JfQCnshVS2jgn8ANXxyCGshck9fyosN8ANwmt3MRWgx2gNfWLoon7uG",
        "signature": "notvalidWnT/sYpR91VXk/cp9Q21/cL+HbW0p8IigBhwQz2R6ITjkQGPahlqS4eBsArXXbnwE95HyyXTZKsZ5m3M7g7nHOb0zbrFHnX1gFU8YKNYR5h5i8hp+IufUnp"
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
	  "validator_nonce": 1,
      "address": "http://127.0.0.1:8080",
      "public": "MIICCgKCAgEA0GqqhNaG+zP9ShFisvwh/WDnlnfEVTR+gLB2diI4x+JSp1zHQ8AOIFssl3j+CXjxVrQ38/WJ6MUjnae1g1eGdt10IP/crbomSFeUXyBlj8FU2wco4CVkPr2CHdir8g/64Rzbs6ZpKMwkqCsOk3pHC3qsgOYgrj84rOe37L3zYarpovVN44zjGqza5LZu1UdpHzEUVGFsaG8B4aC44LRS6/W/FGTUjexamXlncGQDRM0uk00jZsE6K4at/Ai5i72WgRSRWvn0Ki8nbglyHVyqfwZAUZy0Eno8Xq38zOnDvlUbVv75FIjpj4HDibScDDDAd7VKBtZxfhRMDjuD9PXNXDrIC0E8eEku6rT577kY00eARTsHZWh/eQsLUJkK4jVf7rNpVrAY47D7xldWapjSG3Gw7FRfeuvZhGqRy7WVOPzw3adKnpYCc3+bQBep967zN6cLd2X682XxoS4+9/uNXGhY92kwr7JYDvV5yEEQAY78ByS2Q/cfYpHPzijmZl2+5KI06q/5JT0iyOZiz1ba64tVcdScoq/Fp+DaGez3kqfeTM3nYA5QiqkZ+MUjYim6vPf/6bH2nwG7r4HejQ/ifayLqVhj26ypzBFwNi1SuuN8CbOCEWoQdgFf89+dRytp0G5/r7S58LC5bGjMbUNEHs9r5HDwxsdpIgjuqbWf+xkCAwEAAQ==",
      "signature": "notvalid+or3r6hFAfEDJ4LrKKE3EXvJKxxC0yZ+GMBfc+ILLZ1nyPQPDqKbqWzWmAZ87VEb18DO8IjtYzrCu5/O6UqiPfg5P8ObV/D2KYJOsW6ofdch6VI3Te5mdsiCPJxmcJvOrjC1oTvDow4+zRDjmAnnSOhygnI7MAZCZV1JZPdCl0zWwdDcJPm17Rk6o6GVLrZ8V/Kopt5jnMRmy0813smZRnYPN4sLZdVvLSZtbY4RSh41tSWzKzx85pc6dqrjVEzGzp29EDMoWDc6EdfVwdc/eWos6PFiSosOwBsM00Qis6Ty0MR84UlknMUEmTyQ3K5D6W5STnFiGvNi4NzQ5UTttJq1fqQsbSjnQjYDNN9DMQbmuMFt8w0i5f9g6dKB15/Aps22T6ocp7l083ub1lbujjjsedv1ktqCUAw+n/bXPeJ3fK43H9Oh5mMSvkhhmkqojHH+YoKjZuL54fqp3XKqEn6KZuzpg/Yu/O+5S0UlJkVIMMyLcrv2wC4YgaCthLT17m66kRil/a4RFWdKCccWF0LSNOrtoD6CM5hpB4iTFn0MltxpuEyMrEtq6r93/nNh+ZfrVVuMG0BuKp14aKuqw1TiyE4APCZJxsDnr009LookF7ktGvtsBsAXTf0JDiRJKAvFGQ6N2GUSAa0tobCskw0g+zLX5BCe4U8="
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
