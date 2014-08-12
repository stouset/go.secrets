package secrets

import (
	"fmt"
	"testing"
)

func Example() {
	secret, err := NewSecret(8)

	if err != nil {
		return
	}

	// always pair an unlocking method with a deferred lock
	secret.Write()
	defer secret.Lock()

	copy(secret.Slice(), []byte("secrets!"))

	// switch the secret to be readable; deferred lock isn't
	// necessary here because we're already locking at the end of
	// the method
	secret.Read()

	fmt.Printf("%s\n", secret.Slice())

	// not strictly necessary; this will happen when the secret is
	// garbage collected, but being explicit is good hygeine and
	// causes the secret to be wiped from memory immediately
	secret.Wipe()

	// Output: secrets!
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

	fmt.Printf("Secret: 0x%x\n", secret.Slice())
	fmt.Printf("Slice: 0x%x\n", bytes)

	secret.Wipe()

	// Output:
	// Secret: 0x7365637265747321
	// Slice: 0x0000000000000000
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
