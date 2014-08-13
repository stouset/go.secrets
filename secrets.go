// Package secrets creates low-level heap-allocated buffers safe for
// the storage of cryptographic secrets.
//
// A Secret is protected from being read from, written to, or executed
// once allocated. They are prevented from being paged out to swap
// (although systems that hibernate will be able to bypass this
// restriction), they have guard pages and a canary to protect against
// buffer overflows and underflows, and their contents are
// automatically zeroed when they become garbage collected.
//
// A Secret attempts to protect memory contents pessimistically. If
// the memory cannot be protected during initialization, no memory
// will be allocated and an error will be returned. If memory
// protections cannot be maintained during the lifespan of an existing
// Secret, the library will panic.
//
// The use of this package should be limited to storing cryptographic
// secrets. In order to provide the promised protections, allocations
// are significantly larger than the amount of memory requested and
// the number of operations during allocation is more than with
// typical allocators like malloc.
//
// Examples
//
//   // Create a new Secret 32 bytes in size. The Secret is
//   // initialized to zero bytes.
//   secret, err := NewSecret(32)
//
//   // Allow the Secret to be written to. We defer locking the Secret
//   // so we can guarantee that its contents are protected once the
//   // function returns.
//   secret.Write()
//   defer secret.Lock()
//
//   // Read (up to) 32 bytes from stdin into the secret
//   os.Stdin.Read(secret.Slice())
//
//   // This will automatically happen once the Secret is garbage
//   // collected, but being explicit allows the memory to be zeroed
//   // out earlier.
//   secret.Wipe()
//
package secrets

// #cgo pkg-config: libsodium
//
// #include <string.h>
// #include <sys/mman.h>
// #include <unistd.h>
//
// #include <sodium/core.h>
// #include <sodium/randombytes.h>
// #include <sodium/utils.h>
import "C"

import (
	"reflect"
	"runtime"
	"unsafe"
)

var (
	// the size of a page of memory
	pageSize = C.size_t(C.getpagesize())

	// the canary will be filled during init()
	canarySize = C.size_t(128)
	canary     = C.malloc(canarySize)
)

func init() {
	if canary == nil {
		panic("secrets: couldn't allocate memory for a canary")
	}

	if int(C.sodium_init()) != 0 {
		panic("secrets: libsodium couldn't be initialized")
	}

	// give the canary a cryptographically random default value
	C.randombytes_buf(canary, canarySize)
}

// A Secret contains a protected cryptographic secret. The contents of
// the Secret may only be accessed when explicitly unlocked, and its
// memory is zeroed out before being released back to the operating system.
type Secret struct {
	secret *secret
}

// NewSecret creates a new Secret capable of storing len bytes. The
// Secret cannot be read from or written to until unlocked.
//
// If memory allocation fails or memory regions can't be adequately
// protected, an error will be returned.
func NewSecret(
	len int,
) (*Secret, error) {
	var (
		sec Secret
		err error
	)

	sec = Secret{&secret{}}

	// empty secrets are valid, but we don't have anything to do
	if len == 0 {
		return &sec, nil
	}

	if err = sec.secret.alloc(C.size_t(len)); err != nil {
		return nil, err
	}

	return &sec, nil
}

// NewSecretFromBytes creates a new Secret from a preexisting byte
// slice. The contents of the byte slice are zeroed out after they are
// copied into the Secret.
//
// If memory allocation fails or memory regions can't be adequately
// protected, an error will be returned.
//
// Note that a Secret allocated this way cannot make any security
// guarantees about the original contents of the byte slice. They may
// have been copied by other parts of the program, or silently copied
// by the Go runtime. If you must allocate a Secret from a byte slice,
// it should be done as soon as possible after the byte slice has had
// the secret data written to it.
func NewSecretFromBytes(
	data []byte,
) (*Secret, error) {
	var (
		dataPtr, dataSize = _byteSlicePtrSize(data)
		secret, err       = NewSecret(len(data))
	)

	if err != nil {
		return nil, err
	}

	secret.Write()
	defer secret.Lock()

	C.memcpy(secret.Pointer(), dataPtr, dataSize)
	C.sodium_memzero(dataPtr, dataSize)

	return secret, nil
}

// Returns the length of the Secret in bytes.
func (s Secret) Len() int { return int(s.Size()) }

// Returns the C size_t length of the Secret in bytes
func (s Secret) Size() C.size_t { return s.secret.userSize }

// Locks the Secret, preventing any access to its contents.
func (s Secret) Lock() { s.secret.lock() }

// Allows the Secret's contents to be read. Immediately after calling
// this method, always `defer secret.Lock()` to ensure its protection
// is restored.
func (s Secret) Read() { s.secret.unlock(C.PROT_READ) }

// Allows the Secret's contents to be written to. Immediately after
// calling this method, always `defer secret.Lock()` to ensure its
// protection is restored.
func (s Secret) Write() { s.secret.unlock(C.PROT_WRITE) }

// Allows the Secret's contents to be read from and written
// to. Immediately after calling this method, always `defer
// secret.Lock()` to ensure its protection is restored.
func (s Secret) ReadWrite() { s.secret.unlock(C.PROT_READ | C.PROT_WRITE) }

// Returns an unsafe.Pointer pointing to the memory contents of the
// Secret. When accessing memory through this pointer, take care to
// never access more than Len() bytes from this pointer. This pointer
// can only be read from or written to when the Secret itself is
// unlocked.
func (s Secret) Pointer() unsafe.Pointer {
	return s.secret.userPtr
}

// Returns a byte slice containing the contents of the Secret. This
// slice may only be read from or written to when the Secret itself is
// unlocked. Take care not to create copies of the contents of the
// returned slice.
func (s Secret) Slice() []byte {
	sh := reflect.SliceHeader{
		Data: uintptr(s.Pointer()),
		Len:  s.Len(),
		Cap:  s.Len(),
	}

	// cast the address of the SliceHeader into a slice pointer,
	// then take the value of that pointer to get the data as an
	// actual slice
	return *(*[]byte)(unsafe.Pointer(&sh))
}

// Reduces the size of the Secret to len bytes. The location of the
// overflow canary is adjusted to reflect the new size of the
// Secret. If len is larger than the current length of the secret,
// no operation is performed.
func (s Secret) Trim(len int) {
	if len > int(s.secret.userSize) {
		len = int(s.secret.userSize)
	}

	// reduce the size of the secret to the requested length and
	// replace the canary
	s.secret.userSize = C.size_t(len)
	s.secret.guard()
}

// Copies a Secret's contents into a new Secret. If either allocating
// the new Secret or unlocking the existing Secret fails, returns an
// error.
func (s Secret) Copy() (*Secret, error) {
	copy, err := NewSecret(s.Len())

	if err != nil {
		return nil, err
	}

	copy.Write()
	defer copy.Lock()

	s.Read()
	defer s.Lock()

	C.memcpy(
		copy.Pointer(),
		s.Pointer(),
		s.Size(),
	)

	return copy, nil
}

// Compares two Secrets for equality in constant time.
func (s Secret) Equal(other *Secret) bool {
	if s.Len() != other.Len() {
		return false
	}

	s.Read()
	defer s.Lock()

	other.Read()
	defer other.Lock()

	ret := C.sodium_memcmp(
		other.Pointer(),
		s.Pointer(),
		s.Size(),
	)

	return ret == 0
}

// Immediately zeroes out and releases the Secret's memory. Any
// attempt to reuse a Secret after a call to Wipe() will result in
// undefined behavior.
func (s Secret) Wipe() {
	// no need to run the finalizer now; this prevents us from
	// accidentally trying to re-free the same memory
	runtime.SetFinalizer(s.secret, nil)

	// explicitly zero out and free memory
	s.secret.free()
	s.secret = nil
}

// The actual struct that holds pointers to the underlying data for a
// Secret. This is structured so that the secret has a finalizer which
// cleans up and frees allocated memory once it is garbage collected,
// but a Secret can be copied around (for instance, by passing them as
// values to functions) and garbage collected without invoking the
// finalizer.
type secret struct {
	userPtr  unsafe.Pointer
	userSize C.size_t
}

// Allocates enough memory to contain size bytes, plus room for a
// canary and a guard page before and after the allocation. The pages
// are locked into memory.
//
// The allocated memory is zeroed.
func (s *secret) alloc(size C.size_t) error {
	var err error

	// calculate the size of the user region, then allocate enough
	// guarded pages for that amount
	s.userSize = size
	s.userPtr, err = guarded_alloc(s.allocSize())

	if err != nil {
		return err
	}

	// ensure we clean up after ourselves, now that we've
	// allocated memory
	runtime.SetFinalizer(s, func(s *secret) { s.free() })

	// guard the allocated pages
	s.guard()

	s.unlock(C.PROT_WRITE)
	defer s.lock()

	C.sodium_memzero(s.userPtr, s.userSize)

	return nil
}

// Zeroes out the contents of the secret and releases its memory back
// to the system.
func (s *secret) free() {
	// unguard the allocated pages
	s.unguard()

	// free the entire allocated region
	guarded_free(s.userPtr, s.allocSize())

	// don't maintain dangling pointers
	s.userPtr = nil
	s.userSize = 0
}

// Locks the user region into memory and places an overflow canary
// directly adjacent to it. Protects the memory against any access
// before returning.
func (s *secret) guard() error {
	s.unlock(C.PROT_WRITE)

	// we only need to mlock the region we requested; the guard
	// pages can be swapped to disk if the OS wants to
	if ret, err := C.sodium_mlock(s.userPtr, s.allocSize()); ret != 0 {
		return err
	}

	// write the canary immediately after the user region
	C.memcpy(s.canaryPtr(), canary, canarySize)

	// default the user region to being inaccessible
	s.lock()

	return nil
}

// Verifies the overflow canary before unlocking the allocated
// memory. The memory region is allowed to be read and written to once
// this method returns.
func (s *secret) unguard() {
	// ensure the user region can be read from in order to check
	// the canary
	s.unlock(C.PROT_READ)

	// verify the canary
	if C.memcmp(s.canaryPtr(), canary, canarySize) != C.int(0) {
		panic("secrets: buffer overflow canary triggered")
	}

	// allow the user region to be written to so it can be zeroed
	s.unlock(C.PROT_WRITE)

	// wipe the user region (and canary, to avoid it from being leaked)
	C.sodium_munlock(s.userPtr, s.allocSize())

	// finally, completely unlock the user region
	s.unlock(C.PROT_READ | C.PROT_WRITE)
}

// Locks the secret's contents, preventing them from being read,
// written to, or executed.
func (s *secret) lock() {
	if ret, err := C.mprotect(s.userPtr, s.userSize, C.PROT_NONE); ret != 0 {
		panic(err)
	}
}

// Unlocks the secret's contents, giving them the protection level
// specified.
func (s *secret) unlock(prot C.int) {
	if ret, err := C.mprotect(s.userPtr, s.userSize, prot); ret != 0 {
		panic(err)
	}
}

func (s secret) allocSize() C.size_t {
	return s.userSize + canarySize
}

// Returns a pointer to the secret's canary.
func (s secret) canaryPtr() unsafe.Pointer {
	return _ptrAdd(s.userPtr, s.userSize)
}

// Calculates the size of an allocation with enough room for two extra
// guard pages.
func guarded_alloc_size(size C.size_t) C.size_t {
	return 2*pageSize + _pageRound(size)
}

// Allocates the requested amount of memory, plus two guard pages. The
// entire region is protected against any memory access. The pointer
// returned points to a region inbetween the guard pages with enough
// space to contain size bytes. An error is returned if the memory
// can't be allocated or protected.
func guarded_alloc(size C.size_t) (unsafe.Pointer, error) {
	size = guarded_alloc_size(size)

	ptr, err := C.mmap(nil, size, C.PROT_NONE, C.MAP_ANON|C.MAP_PRIVATE, -1, 0)

	if err != nil {
		return nil, err
	}

	// return a pointer to the interior pages
	return _ptrAdd(ptr, pageSize), nil
}

// Frees an earlier allocation of the given number of bytes. Also
// makes sure to free the surrounding pages.
func guarded_free(ptr unsafe.Pointer, size C.size_t) {
	// calculate the true base of the pointer and the size of the
	// allocated region
	ptr = _ptrAdd(ptr, -pageSize)
	size = guarded_alloc_size(size)

	C.munmap(ptr, size)
}

// Rounds size to the next highest page boundary.
func _pageRound(size C.size_t) C.size_t {
	return ((size + pageSize) / pageSize) * pageSize
}

// Returns a pointer to the underlying buffer and the size of a byte slice.
func _byteSlicePtrSize(slice []byte) (unsafe.Pointer, C.size_t) {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&slice))

	return unsafe.Pointer(sh.Data), C.size_t(sh.Len)
}

// Performs pointer arithmetic, adding an offset (positive or
// negative) to the provided pointer.
func _ptrAdd(ptr unsafe.Pointer, offset C.size_t) unsafe.Pointer {
	return unsafe.Pointer(uintptr(ptr) + uintptr(offset))
}