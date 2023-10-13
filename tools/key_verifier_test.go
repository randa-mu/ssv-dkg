package main

import (
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
)

func TestValidKeyValidates(t *testing.T) {
	valid := `
{
  "operators": [
    {
      "address": "http://localhost:8080",
      "public": "MIICCgKCAgEA0GqqhNaG+zP9ShFisvwh/WDnlnfEVTR+gLB2diI4x+JSp1zHQ8AOIFssl3j+CXjxVrQ38/WJ6MUjnae1g1eGdt10IP/crbomSFeUXyBlj8FU2wco4CVkPr2CHdir8g/64Rzbs6ZpKMwkqCsOk3pHC3qsgOYgrj84rOe37L3zYarpovVN44zjGqza5LZu1UdpHzEUVGFsaG8B4aC44LRS6/W/FGTUjexamXlncGQDRM0uk00jZsE6K4at/Ai5i72WgRSRWvn0Ki8nbglyHVyqfwZAUZy0Eno8Xq38zOnDvlUbVv75FIjpj4HDibScDDDAd7VKBtZxfhRMDjuD9PXNXDrIC0E8eEku6rT577kY00eARTsHZWh/eQsLUJkK4jVf7rNpVrAY47D7xldWapjSG3Gw7FRfeuvZhGqRy7WVOPzw3adKnpYCc3+bQBep967zN6cLd2X682XxoS4+9/uNXGhY92kwr7JYDvV5yEEQAY78ByS2Q/cfYpHPzijmZl2+5KI06q/5JT0iyOZiz1ba64tVcdScoq/Fp+DaGez3kqfeTM3nYA5QiqkZ+MUjYim6vPf/6bH2nwG7r4HejQ/ifayLqVhj26ypzBFwNi1SuuN8CbOCEWoQdgFf89+dRytp0G5/r7S58LC5bGjMbUNEHs9r5HDwxsdpIgjuqbWf+xkCAwEAAQ==",
      "signature": "ON7pilM9+or3r6hFAfEDJ4LrKKE3EXvJKxxC0yZ+GMBfc+ILLZ1nyPQPDqKbqWzWmAZ87VEb18DO8IjtYzrCu5/O6UqiPfg5P8ObV/D2KYJOsW6ofdch6VI3Te5mdsiCPJxmcJvOrjC1oTvDow4+zRDjmAnnSOhygnI7MAZCZV1JZPdCl0zWwdDcJPm17Rk6o6GVLrZ8V/Kopt5jnMRmy0813smZRnYPN4sLZdVvLSZtbY4RSh41tSWzKzx85pc6dqrjVEzGzp29EDMoWDc6EdfVwdc/eWos6PFiSosOwBsM00Qis6Ty0MR84UlknMUEmTyQ3K5D6W5STnFiGvNi4NzQ5UTttJq1fqQsbSjnQjYDNN9DMQbmuMFt8w0i5f9g6dKB15/Aps22T6ocp7l083ub1lbujjjsedv1ktqCUAw+n/bXPeJ3fK43H9Oh5mMSvkhhmkqojHH+YoKjZuL54fqp3XKqEn6KZuzpg/Yu/O+5S0UlJkVIMMyLcrv2wC4YgaCthLT17m66kRil/a4RFWdKCccWF0LSNOrtoD6CM5hpB4iTFn0MltxpuEyMrEtq6r93/nNh+ZfrVVuMG0BuKp14aKuqw1TiyE4APCZJxsDnr009LookF7ktGvtsBsAXTf0JDiRJKAvFGQ6N2GUSAa0tobCskw0g+zLX5BCe4U8="
    },
    {
      "address": "https://example.org",
      "public": "MIICCgKCAgEAlrh5+oL/xXisN04ICZfGv5pXMZ3noWjNXwwmyKj7TNUhMSjZB1P3yPO7VZSd+gTugDCS/oMfsy7+hVW+n4RNxIoCpomZ+8J3cbmPjKEsdrwxkXuV1XSrl7AaxjlmPOLekdCul+yvRjgXmeDuz8UsuTFi/acDxadrH4DHk76O+9RpP4caagInx2jtS9wHt3W4ZSG9wttIT98DiBjy2dGXkzEDn3m8WhMkMHxCIYbXW75EkjZtDJEwFpBDgzVn+3ntSbBqDXD9BMl1KeWSb/diV7qiN2p8+UBz+xZdol1SPx2dmqwHske9IKevywjGgwa0yXCzwgeK2zb2L5ALEpgDXGeMt8PJ816d1v9fVQFY0Dwh3lIucGjZ1x+raIstpXFNbS4UEkndTYD604OnbCYp32LFTUGnjPt7tWW0YhLhvCU3Cw0oQ/OprC3NlUqRb1INV2pYatGqEpOvL/QZO7zft1/WOu4nBoydI9ZmJ8sN9cCOx9OyuOQjNHy4HbYBvSPyFKI4ZgOeIjmQiyWHtwWYFTZ+AyUH4trK5NIXoDnig9s60pjtfUVQISo6Xoek4wE5LrviBk7SoIbChKbSp2W8WQGCCCjRWeKhdyfby0YqHlf2qUitizA8DYlKNJ4vFVkNiycNcctt3XUdXcD4FDqiPGm7x3XeZOSML2uYnPtofOMCAwEAAQ==",
      "signature": "XK5+Im2DyrzsGpnV7kmb3Gm67K23fKintYGRF2kSGycOjQ/1xTlukM4ZCN99KLrsO+EoMj5GB+mVm+cXltQaEOFDba+u4Jxk+J1rqidTt5MiCDnJBg8fkywHqLPYbxad/OQ+qqbzky4zsBf3ZZhXr7Lejqw469iiLJ6F8g1rhxl32prugcC3vj+fikZ/9d/L2XrrP55YhVDZzRRf3kWyfPicdw1u3sZevY6eHOIm2lo7hz7JCBaKb9io9Hmwaah9ZueVucr9/pJTu8NhHno4GVWA2qF0alwE+Emyvd8GDi0Mo63hKWzOKkrev6sF7aKiF2UmKoGRQgiKDXl1DuZBuCE60jiJW71blMwyOyDNjCMttngl+K1r1Dd3MCKn+3jtzCjcbLZNE4JPWZQ74s4Rxygx/rqMY5aZ5aLuWI2OqWC9Qyy2su4BWvzMUjmP9TiYcs0yvybMIEoa29mx2BfQ0u4dXjaXBjNjkCwL+e0HIgiKZrjOw6b1JHmqTJSlc/dURfxbS8wPax5yUzkzyPlPGi6o2VSgCKXjcVyaesfcmyJhUhFlpGSG3LCawPAXUH2q6e7GUW+qo8df8BW48Kd95NOuZIboe238R8h6AO5psjEND2TD0p2y72nJWTpYI5s3cF0Vb4h91vvCM7kSCVNoR6wSoob924D9WwAP6yfjLCA="
    }
  ]
}`

	p := path.Join(t.TempDir(), "somekeys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}

	require.NoError(t, verifyKeys(p))
}

func TestInvalidAddressReturnsError(t *testing.T) {
	invalid := `
{
  "operators": [
    {
      "address": "http://notthesameaddressaspublickey:8080",
      "public": "MIICCgKCAgEA0GqqhNaG+zP9ShFisvwh/WDnlnfEVTR+gLB2diI4x+JSp1zHQ8AOIFssl3j+CXjxVrQ38/WJ6MUjnae1g1eGdt10IP/crbomSFeUXyBlj8FU2wco4CVkPr2CHdir8g/64Rzbs6ZpKMwkqCsOk3pHC3qsgOYgrj84rOe37L3zYarpovVN44zjGqza5LZu1UdpHzEUVGFsaG8B4aC44LRS6/W/FGTUjexamXlncGQDRM0uk00jZsE6K4at/Ai5i72WgRSRWvn0Ki8nbglyHVyqfwZAUZy0Eno8Xq38zOnDvlUbVv75FIjpj4HDibScDDDAd7VKBtZxfhRMDjuD9PXNXDrIC0E8eEku6rT577kY00eARTsHZWh/eQsLUJkK4jVf7rNpVrAY47D7xldWapjSG3Gw7FRfeuvZhGqRy7WVOPzw3adKnpYCc3+bQBep967zN6cLd2X682XxoS4+9/uNXGhY92kwr7JYDvV5yEEQAY78ByS2Q/cfYpHPzijmZl2+5KI06q/5JT0iyOZiz1ba64tVcdScoq/Fp+DaGez3kqfeTM3nYA5QiqkZ+MUjYim6vPf/6bH2nwG7r4HejQ/ifayLqVhj26ypzBFwNi1SuuN8CbOCEWoQdgFf89+dRytp0G5/r7S58LC5bGjMbUNEHs9r5HDwxsdpIgjuqbWf+xkCAwEAAQ==",
      "signature": "ON7pilM9+or3r6hFAfEDJ4LrKKE3EXvJKxxC0yZ+GMBfc+ILLZ1nyPQPDqKbqWzWmAZ87VEb18DO8IjtYzrCu5/O6UqiPfg5P8ObV/D2KYJOsW6ofdch6VI3Te5mdsiCPJxmcJvOrjC1oTvDow4+zRDjmAnnSOhygnI7MAZCZV1JZPdCl0zWwdDcJPm17Rk6o6GVLrZ8V/Kopt5jnMRmy0813smZRnYPN4sLZdVvLSZtbY4RSh41tSWzKzx85pc6dqrjVEzGzp29EDMoWDc6EdfVwdc/eWos6PFiSosOwBsM00Qis6Ty0MR84UlknMUEmTyQ3K5D6W5STnFiGvNi4NzQ5UTttJq1fqQsbSjnQjYDNN9DMQbmuMFt8w0i5f9g6dKB15/Aps22T6ocp7l083ub1lbujjjsedv1ktqCUAw+n/bXPeJ3fK43H9Oh5mMSvkhhmkqojHH+YoKjZuL54fqp3XKqEn6KZuzpg/Yu/O+5S0UlJkVIMMyLcrv2wC4YgaCthLT17m66kRil/a4RFWdKCccWF0LSNOrtoD6CM5hpB4iTFn0MltxpuEyMrEtq6r93/nNh+ZfrVVuMG0BuKp14aKuqw1TiyE4APCZJxsDnr009LookF7ktGvtsBsAXTf0JDiRJKAvFGQ6N2GUSAa0tobCskw0g+zLX5BCe4U8="
    }
  ]
}`

	p := path.Join(t.TempDir(), "somekeys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(invalid))
	if err != nil {
		t.Fatal(err)
	}

	require.Error(t, verifyKeys(p))
}

func TestInvalidSignatureReturnsError(t *testing.T) {
	invalid := `
{
  "operators": [
    {
      "address": "http://localhost:8080",
      "public": "MIICCgKCAgEA0GqqhNaG+zP9ShFisvwh/WDnlnfEVTR+gLB2diI4x+JSp1zHQ8AOIFssl3j+CXjxVrQ38/WJ6MUjnae1g1eGdt10IP/crbomSFeUXyBlj8FU2wco4CVkPr2CHdir8g/64Rzbs6ZpKMwkqCsOk3pHC3qsgOYgrj84rOe37L3zYarpovVN44zjGqza5LZu1UdpHzEUVGFsaG8B4aC44LRS6/W/FGTUjexamXlncGQDRM0uk00jZsE6K4at/Ai5i72WgRSRWvn0Ki8nbglyHVyqfwZAUZy0Eno8Xq38zOnDvlUbVv75FIjpj4HDibScDDDAd7VKBtZxfhRMDjuD9PXNXDrIC0E8eEku6rT577kY00eARTsHZWh/eQsLUJkK4jVf7rNpVrAY47D7xldWapjSG3Gw7FRfeuvZhGqRy7WVOPzw3adKnpYCc3+bQBep967zN6cLd2X682XxoS4+9/uNXGhY92kwr7JYDvV5yEEQAY78ByS2Q/cfYpHPzijmZl2+5KI06q/5JT0iyOZiz1ba64tVcdScoq/Fp+DaGez3kqfeTM3nYA5QiqkZ+MUjYim6vPf/6bH2nwG7r4HejQ/ifayLqVhj26ypzBFwNi1SuuN8CbOCEWoQdgFf89+dRytp0G5/r7S58LC5bGjMbUNEHs9r5HDwxsdpIgjuqbWf+xkCAwEAAQ==",
      "signature": "notvalid+or3r6hFAfEDJ4LrKKE3EXvJKxxC0yZ+GMBfc+ILLZ1nyPQPDqKbqWzWmAZ87VEb18DO8IjtYzrCu5/O6UqiPfg5P8ObV/D2KYJOsW6ofdch6VI3Te5mdsiCPJxmcJvOrjC1oTvDow4+zRDjmAnnSOhygnI7MAZCZV1JZPdCl0zWwdDcJPm17Rk6o6GVLrZ8V/Kopt5jnMRmy0813smZRnYPN4sLZdVvLSZtbY4RSh41tSWzKzx85pc6dqrjVEzGzp29EDMoWDc6EdfVwdc/eWos6PFiSosOwBsM00Qis6Ty0MR84UlknMUEmTyQ3K5D6W5STnFiGvNi4NzQ5UTttJq1fqQsbSjnQjYDNN9DMQbmuMFt8w0i5f9g6dKB15/Aps22T6ocp7l083ub1lbujjjsedv1ktqCUAw+n/bXPeJ3fK43H9Oh5mMSvkhhmkqojHH+YoKjZuL54fqp3XKqEn6KZuzpg/Yu/O+5S0UlJkVIMMyLcrv2wC4YgaCthLT17m66kRil/a4RFWdKCccWF0LSNOrtoD6CM5hpB4iTFn0MltxpuEyMrEtq6r93/nNh+ZfrVVuMG0BuKp14aKuqw1TiyE4APCZJxsDnr009LookF7ktGvtsBsAXTf0JDiRJKAvFGQ6N2GUSAa0tobCskw0g+zLX5BCe4U8="
    }
  ]
}`

	p := path.Join(t.TempDir(), "somekeys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(invalid))
	if err != nil {
		t.Fatal(err)
	}

	require.Error(t, verifyKeys(p))
}

func TestInvalidJsonReturnsError(t *testing.T) {
	// missing closing [
	invalid := `
{
  "operators": [
    {
      "address": "http://localhost:8080",
      "public": "MIICCgKCAgEA0GqqhNaG+zP9ShFisvwh/WDnlnfEVTR+gLB2diI4x+JSp1zHQ8AOIFssl3j+CXjxVrQ38/WJ6MUjnae1g1eGdt10IP/crbomSFeUXyBlj8FU2wco4CVkPr2CHdir8g/64Rzbs6ZpKMwkqCsOk3pHC3qsgOYgrj84rOe37L3zYarpovVN44zjGqza5LZu1UdpHzEUVGFsaG8B4aC44LRS6/W/FGTUjexamXlncGQDRM0uk00jZsE6K4at/Ai5i72WgRSRWvn0Ki8nbglyHVyqfwZAUZy0Eno8Xq38zOnDvlUbVv75FIjpj4HDibScDDDAd7VKBtZxfhRMDjuD9PXNXDrIC0E8eEku6rT577kY00eARTsHZWh/eQsLUJkK4jVf7rNpVrAY47D7xldWapjSG3Gw7FRfeuvZhGqRy7WVOPzw3adKnpYCc3+bQBep967zN6cLd2X682XxoS4+9/uNXGhY92kwr7JYDvV5yEEQAY78ByS2Q/cfYpHPzijmZl2+5KI06q/5JT0iyOZiz1ba64tVcdScoq/Fp+DaGez3kqfeTM3nYA5QiqkZ+MUjYim6vPf/6bH2nwG7r4HejQ/ifayLqVhj26ypzBFwNi1SuuN8CbOCEWoQdgFf89+dRytp0G5/r7S58LC5bGjMbUNEHs9r5HDwxsdpIgjuqbWf+xkCAwEAAQ==",
      "signature": "notvalid+or3r6hFAfEDJ4LrKKE3EXvJKxxC0yZ+GMBfc+ILLZ1nyPQPDqKbqWzWmAZ87VEb18DO8IjtYzrCu5/O6UqiPfg5P8ObV/D2KYJOsW6ofdch6VI3Te5mdsiCPJxmcJvOrjC1oTvDow4+zRDjmAnnSOhygnI7MAZCZV1JZPdCl0zWwdDcJPm17Rk6o6GVLrZ8V/Kopt5jnMRmy0813smZRnYPN4sLZdVvLSZtbY4RSh41tSWzKzx85pc6dqrjVEzGzp29EDMoWDc6EdfVwdc/eWos6PFiSosOwBsM00Qis6Ty0MR84UlknMUEmTyQ3K5D6W5STnFiGvNi4NzQ5UTttJq1fqQsbSjnQjYDNN9DMQbmuMFt8w0i5f9g6dKB15/Aps22T6ocp7l083ub1lbujjjsedv1ktqCUAw+n/bXPeJ3fK43H9Oh5mMSvkhhmkqojHH+YoKjZuL54fqp3XKqEn6KZuzpg/Yu/O+5S0UlJkVIMMyLcrv2wC4YgaCthLT17m66kRil/a4RFWdKCccWF0LSNOrtoD6CM5hpB4iTFn0MltxpuEyMrEtq6r93/nNh+ZfrVVuMG0BuKp14aKuqw1TiyE4APCZJxsDnr009LookF7ktGvtsBsAXTf0JDiRJKAvFGQ6N2GUSAa0tobCskw0g+zLX5BCe4U8="
    }
}`

	p := path.Join(t.TempDir(), "somekeys.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte(invalid))
	if err != nil {
		t.Fatal(err)
	}

	require.Error(t, verifyKeys(p))
}

func TestNonExistentFileReturnsError(t *testing.T) {
	require.Error(t, verifyKeys("somenonsensepath"))
}
