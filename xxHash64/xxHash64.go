// Package xxHash64 implements the very fast xxHash hashing algorithm (64 bits version).
// (https://github.com/Cyan4973/xxHash/)
package xxHash64

import "hash"

const (
	prime64_1 = 11400714785074694791
	prime64_2 = 14029467366897019727
	prime64_3 = 1609587929392839161
	prime64_4 = 9650029242287828579
	prime64_5 = 2870177450012600261
)

type xxHash struct {
	seed     uint64
	v1       uint64
	v2       uint64
	v3       uint64
	v4       uint64
	totalLen uint64
	buf      []byte
}

// New returns a new Hash64 instance.
func New(seed uint64) hash.Hash64 {
	xxh := &xxHash{
		seed: seed,
		buf:  make([]byte, 0, 32),
	}
	xxh.Reset()
	return xxh
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (xxh xxHash) Sum(b []byte) []byte {
	h64 := xxh.Sum64()
	return append(b, byte(h64>>56), byte(h64>>48), byte(h64>>40), byte(h64>>32), byte(h64>>24), byte(h64>>16), byte(h64>>8), byte(h64))
}

// Reset resets the Hash to its initial state.
func (xxh *xxHash) Reset() {
	xxh.v1 = xxh.seed + prime64_1 + prime64_2
	xxh.v2 = xxh.seed + prime64_2
	xxh.v3 = xxh.seed
	xxh.v4 = xxh.seed - prime64_1
	xxh.totalLen = 0
	xxh.buf = xxh.buf[:0]
}

// Size returns the number of bytes returned by Sum().
func (xxh *xxHash) Size() int {
	return 8
}

// BlockSize gives the minimum number of bytes accepted by Write().
func (xxh *xxHash) BlockSize() int {
	return 1
}

// Write adds input bytes to the Hash.
// It never returns an error.
func (xxh *xxHash) Write(input []byte) (int, error) {
	n := len(input)
	m := len(xxh.buf)

	xxh.totalLen += uint64(n)

	r := 32 - m
	if n < r {
		xxh.buf = append(xxh.buf, input...)
		return n, nil
	}

	p := 0
	if m > 0 {
		// some data left from previous update
		xxh.buf = append(xxh.buf, input[:r]...)

		// fast rotl(31)
		p64 := xxh.v1 + (uint64(xxh.buf[p+7])<<56|uint64(xxh.buf[p+6])<<48|uint64(xxh.buf[p+5])<<40|uint64(xxh.buf[p+4])<<32|uint64(xxh.buf[p+3])<<24|uint64(xxh.buf[p+2])<<16|uint64(xxh.buf[p+1])<<8|uint64(xxh.buf[p]))*prime64_2
		xxh.v1 = (p64<<31 | p64>>33) * prime64_1
		p += 8
		p64 = xxh.v2 + (uint64(xxh.buf[p+7])<<56|uint64(xxh.buf[p+6])<<48|uint64(xxh.buf[p+5])<<40|uint64(xxh.buf[p+4])<<32|uint64(xxh.buf[p+3])<<24|uint64(xxh.buf[p+2])<<16|uint64(xxh.buf[p+1])<<8|uint64(xxh.buf[p]))*prime64_2
		xxh.v2 = (p64<<31 | p64>>33) * prime64_1
		p += 8
		p64 = xxh.v3 + (uint64(xxh.buf[p+7])<<56|uint64(xxh.buf[p+6])<<48|uint64(xxh.buf[p+5])<<40|uint64(xxh.buf[p+4])<<32|uint64(xxh.buf[p+3])<<24|uint64(xxh.buf[p+2])<<16|uint64(xxh.buf[p+1])<<8|uint64(xxh.buf[p]))*prime64_2
		xxh.v3 = (p64<<31 | p64>>33) * prime64_1
		p += 8
		p64 = xxh.v4 + (uint64(xxh.buf[p+7])<<56|uint64(xxh.buf[p+6])<<48|uint64(xxh.buf[p+5])<<40|uint64(xxh.buf[p+4])<<32|uint64(xxh.buf[p+3])<<24|uint64(xxh.buf[p+2])<<16|uint64(xxh.buf[p+1])<<8|uint64(xxh.buf[p]))*prime64_2
		xxh.v4 = (p64<<31 | p64>>33) * prime64_1

		p = r
		xxh.buf = xxh.buf[:0]
	}

	for n := n - 32; p <= n; {
		p64 := xxh.v1 + (uint64(input[p+7])<<56|uint64(input[p+6])<<48|uint64(input[p+5])<<40|uint64(input[p+4])<<32|uint64(input[p+3])<<24|uint64(input[p+2])<<16|uint64(input[p+1])<<8|uint64(input[p]))*prime64_2
		xxh.v1 = (p64<<31 | p64>>33) * prime64_1
		p += 8
		p64 = xxh.v2 + (uint64(input[p+7])<<56|uint64(input[p+6])<<48|uint64(input[p+5])<<40|uint64(input[p+4])<<32|uint64(input[p+3])<<24|uint64(input[p+2])<<16|uint64(input[p+1])<<8|uint64(input[p]))*prime64_2
		xxh.v2 = (p64<<31 | p64>>33) * prime64_1
		p += 8
		p64 = xxh.v3 + (uint64(input[p+7])<<56|uint64(input[p+6])<<48|uint64(input[p+5])<<40|uint64(input[p+4])<<32|uint64(input[p+3])<<24|uint64(input[p+2])<<16|uint64(input[p+1])<<8|uint64(input[p]))*prime64_2
		xxh.v3 = (p64<<31 | p64>>33) * prime64_1
		p += 8
		p64 = xxh.v4 + (uint64(input[p+7])<<56|uint64(input[p+6])<<48|uint64(input[p+5])<<40|uint64(input[p+4])<<32|uint64(input[p+3])<<24|uint64(input[p+2])<<16|uint64(input[p+1])<<8|uint64(input[p]))*prime64_2
		xxh.v4 = (p64<<31 | p64>>33) * prime64_1
		p += 8
	}

	xxh.buf = append(xxh.buf, input[p:]...)

	return n, nil
}

// Sum64 returns the 64bits Hash value.
func (xxh *xxHash) Sum64() uint64 {
	var h64 uint64
	if xxh.totalLen >= 32 {
		h64 = ((xxh.v1 << 1) | (xxh.v1 >> 63)) +
			((xxh.v2 << 7) | (xxh.v2 >> 57)) +
			((xxh.v3 << 12) | (xxh.v3 >> 52)) +
			((xxh.v4 << 18) | (xxh.v4 >> 46))

		xxh.v1 *= prime64_2
		h64 ^= ((xxh.v1 << 31) | (xxh.v1 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4

		xxh.v2 *= prime64_2
		h64 ^= ((xxh.v2 << 31) | (xxh.v2 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4

		xxh.v3 *= prime64_2
		h64 ^= ((xxh.v3 << 31) | (xxh.v3 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4

		xxh.v4 *= prime64_2
		h64 ^= ((xxh.v4 << 31) | (xxh.v4 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4 + xxh.totalLen
	} else {
		h64 = xxh.seed + prime64_5 + xxh.totalLen
	}

	p := 0
	n := len(xxh.buf)
	for n := n - 8; p <= n; p += 8 {
		p64 := (uint64(xxh.buf[p+7])<<56 | uint64(xxh.buf[p+6])<<48 | uint64(xxh.buf[p+5])<<40 | uint64(xxh.buf[p+4])<<32 | uint64(xxh.buf[p+3])<<24 | uint64(xxh.buf[p+2])<<16 | uint64(xxh.buf[p+1])<<8 | uint64(xxh.buf[p])) * prime64_2
		h64 ^= ((p64 << 31) | (p64 >> 33)) * prime64_1
		h64 = ((h64<<27)|(h64>>37))*prime64_1 + prime64_4
	}
	if p+4 <= n {
		h64 ^= (uint64(xxh.buf[p+3])<<24 | uint64(xxh.buf[p+2])<<16 | uint64(xxh.buf[p+1])<<8 | uint64(xxh.buf[p])) * prime64_1
		h64 = ((h64<<23)|(h64>>41))*prime64_2 + prime64_3
		p += 4
	}
	for ; p < n; p++ {
		h64 ^= uint64(xxh.buf[p]) * prime64_5
		h64 = ((h64 << 11) | (h64 >> 53)) * prime64_1
	}

	h64 ^= h64 >> 33
	h64 *= prime64_2
	h64 ^= h64 >> 29
	h64 *= prime64_3
	h64 ^= h64 >> 32

	return h64
}

// Checksum returns the 64bits Hash value.
func Checksum(input []byte, seed uint64) uint64 {
	x := New(seed)
	x.Write(input)
	return x.Sum64()
}
