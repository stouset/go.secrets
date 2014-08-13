package secrets

import (
	"fmt"
	"testing"
)

func ExampleNewSecret() {
	// allocate a new 8-byte secret
	secret, err := NewSecret(8)

	if err != nil {
		return
	}

	// allow the secret to be read; good hygeine dictates that the
	// Lock() should be deferred, so it is guaranteed to happen
	// when the method returns
	secret.Read()
	defer secret.Lock()

	fmt.Printf("0x%x", secret.Slice())

	// while not strictly necessary, explicitly wiping the secret
	// when done is also good hygeine; this will happen when
	// the secret is garbage collected, but doing it explicitly
	// causes the memory to be zeroed immediately
	secret.Wipe()

	// Output: 0x0000000000000000
}

func ExampleNewSecretFromBytes() {
	var (
		bytes       = []byte("secrets!")
		secret, err = NewSecretFromBytes(bytes)
	)

	if err != nil {
		return
	}

	secret.Read()
	defer secret.Lock()

	fmt.Printf("0x%x", secret.Slice())

	secret.Wipe()

	// Output: 0x7365637265747321
}

func ExampleNewSecretFromBytes_zeroing() {
	var (
		bytes  = []byte("secrets!")
		_, err = NewSecretFromBytes(bytes)
	)

	if err != nil {
		return
	}

	fmt.Printf("0x%x", bytes)

	// Output: 0x0000000000000000
}

func ExampleSecret_Equal() {
	var (
		secret1, _ = NewSecretFromBytes([]byte("secret"))
		secret2, _ = NewSecretFromBytes([]byte("secret"))
		secret3, _ = NewSecretFromBytes([]byte("secrex"))
	)

	fmt.Printf("%t %t", secret1.Equal(secret2), secret1.Equal(secret3))

	// Output: true false
}

func ExampleSecret_Trim() {
	secret, err := NewSecretFromBytes([]byte("secret!"))

	if err != nil {
		return
	}

	secret.Trim(4)

	secret.Read()
	defer secret.Lock()

	fmt.Printf("%s", secret.Slice())

	secret.Wipe()

	// Output: secr
}

func ExampleSecret_Wipe() {
	secret, err := NewSecretFromBytes([]byte("secret!"))

	if err != nil {
		return
	}

	secret.Wipe()

	// The pointer to the Secret should be NULL
	fmt.Printf("%x\n", secret.Pointer())

	// Output: 0
}

func TestNewSecret(t *testing.T) {
	var (
		secret1 *Secret
		secret2 *Secret
		err     error
	)

	secret1, err = NewSecret(32)

	if err != nil {
		t.Error("NewSecret(32) = _, err; want nil")
	}

	secret1.Write()
	defer secret1.Lock()

	copy(secret1.Slice(), "cryptographic secrets are secret")

	secret2, err = secret1.Copy()

	if err != nil {
		t.Error("Copy() = _, err; want nil")
	}

	if !secret1.Equal(secret2) {
		t.Error("sec1.Equal(sec2) = false; want true")
	}
}

func TestEmptySecret(t *testing.T) {
	var (
		secret1 *Secret
		secret2 *Secret
		secret3 *Secret
		err     error
	)

	secret1, err = NewSecret(0)

	if err != nil {
		t.Error("NewSecret(0) = _, err; want nil")
	}

	secret2, err = NewSecretFromBytes([]byte(""))

	if err != nil {
		t.Error("NewSecretFromBytes(\"\") = _, err; want nil")
	}

	secret3, err = NewSecretFromBytes([]byte("xyz"))

	if err != nil {
		t.Error("NewSecretFromBytes(\"xyz\") = _, err; want nil")
	}

	if !secret1.Equal(secret2) {
		t.Error("secret1.Equal(secret2) = false, _; want true")

	}

	if secret1.Equal(secret3) {
		t.Error("secret1.Equal(secret3) = true, _; want false")
	}
}

func TestSecretCanary(t *testing.T) {
	var (
		secret, _ = NewSecret(32)
		slice     = secret.Slice()
	)

	// trim the secret by one byte
	secret.Trim(31)

	secret.Write()
	defer secret.Lock()

	defer func() {
		if recover() == nil {
			t.Error("secret's canary should have triggered")
		}
	}()

	// attempt to write past the secret's new length
	slice[31] = 42

	// the canary should trigger when the secret is wiped
	secret.Wipe()
}
