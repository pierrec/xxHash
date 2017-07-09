// Package xxHash64 implements the very fast xxHash hashing algorithm (64 bits version).
// (https://github.com/Cyan4973/xxHash/)
package xxHash64

import (
	"hash"
	"unsafe"
)

const (
	prime64_1 = 11400714785074694791
	prime64_2 = 14029467366897019727
	prime64_3 = 1609587929392839161
	prime64_4 = 9650029242287828579
	prime64_5 = 2870177450012600261
)

var littleEndian bool

func init() {
	b := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	actual := *(*uint64)(unsafe.Pointer(&b[0]))
	expected := uint64(0)
	for i, v := range b {
		expected += uint64(v) << (uint(i) * 8)
	}
	littleEndian = actual == expected
}

type xxHash struct {
	seed     uint64
	v1       uint64
	v2       uint64
	v3       uint64
	v4       uint64
	totalLen uint64
	buf      [32]byte
	bufused  int
}

// New returns a new Hash64 instance.
func New(seed uint64) hash.Hash64 {
	xxh := &xxHash{seed: seed}
	xxh.Reset()
	return xxh
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (xxh xxHash) Sum(b []byte) []byte {
	h64 := xxh.Sum64()
	return append(b, byte(h64), byte(h64>>8), byte(h64>>16), byte(h64>>24), byte(h64>>32), byte(h64>>40), byte(h64>>48), byte(h64>>56))
}

// Reset resets the Hash to its initial state.
func (xxh *xxHash) Reset() {
	xxh.v1 = xxh.seed + prime64_1 + prime64_2
	xxh.v2 = xxh.seed + prime64_2
	xxh.v3 = xxh.seed
	xxh.v4 = xxh.seed - prime64_1
	xxh.totalLen = 0
	xxh.bufused = 0
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
	m := xxh.bufused

	xxh.totalLen += uint64(n)

	r := len(xxh.buf) - m
	if n < r {
		copy(xxh.buf[m:], input)
		xxh.bufused += len(input)
		return n, nil
	}

	p := 0
	if m > 0 {
		// some data left from previous update
		copy(xxh.buf[xxh.bufused:], input[:r])
		xxh.bufused += len(input) - r

		// fast rotl(31)
		if littleEndian {
			ptr := uintptr(unsafe.Pointer(&xxh.buf[p]))
			p64 := xxh.v1 + *(*uint64)(unsafe.Pointer(ptr))*prime64_2
			xxh.v1 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v2 + *(*uint64)(unsafe.Pointer(ptr + 8))*prime64_2
			xxh.v2 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v3 + *(*uint64)(unsafe.Pointer(ptr + 16))*prime64_2
			xxh.v3 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v4 + *(*uint64)(unsafe.Pointer(ptr + 24))*prime64_2
			xxh.v4 = (p64<<31 | p64>>33) * prime64_1
		} else {
			p64 := xxh.v1 + (uint64(xxh.buf[0+7])<<56|uint64(xxh.buf[0+6])<<48|uint64(xxh.buf[0+5])<<40|uint64(xxh.buf[0+4])<<32|uint64(xxh.buf[0+3])<<24|uint64(xxh.buf[0+2])<<16|uint64(xxh.buf[0+1])<<8|uint64(xxh.buf[0]))*prime64_2
			xxh.v1 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v2 + (uint64(xxh.buf[8+7])<<56|uint64(xxh.buf[8+6])<<48|uint64(xxh.buf[8+5])<<40|uint64(xxh.buf[8+4])<<32|uint64(xxh.buf[8+3])<<24|uint64(xxh.buf[8+2])<<16|uint64(xxh.buf[8+1])<<8|uint64(xxh.buf[8]))*prime64_2
			xxh.v2 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v3 + (uint64(xxh.buf[16+7])<<56|uint64(xxh.buf[16+6])<<48|uint64(xxh.buf[16+5])<<40|uint64(xxh.buf[16+4])<<32|uint64(xxh.buf[16+3])<<24|uint64(xxh.buf[16+2])<<16|uint64(xxh.buf[16+1])<<8|uint64(xxh.buf[16]))*prime64_2
			xxh.v3 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v4 + (uint64(xxh.buf[24+7])<<56|uint64(xxh.buf[24+6])<<48|uint64(xxh.buf[24+5])<<40|uint64(xxh.buf[24+4])<<32|uint64(xxh.buf[24+3])<<24|uint64(xxh.buf[24+2])<<16|uint64(xxh.buf[24+1])<<8|uint64(xxh.buf[24]))*prime64_2
			xxh.v4 = (p64<<31 | p64>>33) * prime64_1
		}
		p = r
		xxh.bufused = 0
	}

	if p > n-32 {
		// Nothing to do
	} else if littleEndian {
		ptr := uintptr(unsafe.Pointer(&input[p]))
		for n := n - 32; p <= n; p += 32 {
			p64 := xxh.v1 + *(*uint64)(unsafe.Pointer(ptr))*prime64_2
			xxh.v1 = (p64<<31 | p64>>33) * prime64_1
			ptr += 8
			p64 = xxh.v2 + *(*uint64)(unsafe.Pointer(ptr))*prime64_2
			xxh.v2 = (p64<<31 | p64>>33) * prime64_1
			ptr += 8
			p64 = xxh.v3 + *(*uint64)(unsafe.Pointer(ptr))*prime64_2
			xxh.v3 = (p64<<31 | p64>>33) * prime64_1
			ptr += 8
			p64 = xxh.v4 + *(*uint64)(unsafe.Pointer(ptr))*prime64_2
			xxh.v4 = (p64<<31 | p64>>33) * prime64_1
			ptr += 8
		}
	} else {
		for n := n - 32; p <= n; p += 32 {
			sub := input[p : p+32]
			p64 := xxh.v1 + (uint64(sub[0+7])<<56|uint64(sub[0+6])<<48|uint64(sub[0+5])<<40|uint64(sub[0+4])<<32|uint64(sub[0+3])<<24|uint64(sub[0+2])<<16|uint64(sub[0+1])<<8|uint64(sub[0]))*prime64_2
			xxh.v1 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v2 + (uint64(sub[8+7])<<56|uint64(sub[8+6])<<48|uint64(sub[8+5])<<40|uint64(sub[8+4])<<32|uint64(sub[8+3])<<24|uint64(sub[8+2])<<16|uint64(sub[8+1])<<8|uint64(sub[8]))*prime64_2
			xxh.v2 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v3 + (uint64(sub[16+7])<<56|uint64(sub[16+6])<<48|uint64(sub[16+5])<<40|uint64(sub[16+4])<<32|uint64(sub[16+3])<<24|uint64(sub[16+2])<<16|uint64(sub[16+1])<<8|uint64(sub[16]))*prime64_2
			xxh.v3 = (p64<<31 | p64>>33) * prime64_1
			p64 = xxh.v4 + (uint64(sub[24+7])<<56|uint64(sub[24+6])<<48|uint64(sub[24+5])<<40|uint64(sub[24+4])<<32|uint64(sub[24+3])<<24|uint64(sub[24+2])<<16|uint64(sub[24+1])<<8|uint64(sub[24]))*prime64_2
			xxh.v4 = (p64<<31 | p64>>33) * prime64_1
		}
	}

	copy(xxh.buf[xxh.bufused:], input[p:])
	xxh.bufused += len(input) - p

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
	if littleEndian {
		p := 0
		n := xxh.bufused
		ptr := uintptr(unsafe.Pointer(&xxh.buf[0]))
		for n := n - 8; p <= n; p += 8 {
			p64 := *(*uint64)(unsafe.Pointer(ptr)) * prime64_2
			h64 ^= ((p64 << 31) | (p64 >> 33)) * prime64_1
			h64 = ((h64<<27)|(h64>>37))*prime64_1 + prime64_4
			ptr += 8
		}
		if p+4 <= n {
			p32 := *(*uint32)(unsafe.Pointer(ptr))
			h64 ^= uint64(p32) * prime64_1
			h64 = ((h64<<23)|(h64>>41))*prime64_2 + prime64_3
			p += 4
			ptr += 4
		}
		for ; p < n; p++ {
			h64 ^= uint64(xxh.buf[p]) * prime64_5
			h64 = ((h64 << 11) | (h64 >> 53)) * prime64_1
		}
	} else {
		p := 0
		n := xxh.bufused
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
	n := len(input)
	var h64 uint64

	if n >= 32 {
		v1 := seed + prime64_1 + prime64_2
		v2 := seed + prime64_2
		v3 := seed
		v4 := seed - prime64_1
		p := 0
		if n < 32 {
			// Nothing to do
		} else if littleEndian {
			ptr := uintptr(unsafe.Pointer(&input[0]))
			for n := n - 32; p <= n; p += 32 {
				v1 += *(*uint64)(unsafe.Pointer(ptr)) * prime64_2
				v1 = (v1<<31 | v1>>33) * prime64_1
				ptr += 8
				v2 += *(*uint64)(unsafe.Pointer(ptr)) * prime64_2
				v2 = (v2<<31 | v2>>33) * prime64_1
				ptr += 8
				v3 += *(*uint64)(unsafe.Pointer(ptr)) * prime64_2
				v3 = (v3<<31 | v3>>33) * prime64_1
				ptr += 8
				v4 += *(*uint64)(unsafe.Pointer(ptr)) * prime64_2
				v4 = (v4<<31 | v4>>33) * prime64_1
				ptr += 8
			}
		} else {
			for n := n - 32; p <= n; p += 32 {
				sub := input[p : p+32]
				p64 := v1 + (uint64(sub[0+7])<<56|uint64(sub[0+6])<<48|uint64(sub[0+5])<<40|uint64(sub[0+4])<<32|uint64(sub[0+3])<<24|uint64(sub[0+2])<<16|uint64(sub[0+1])<<8|uint64(sub[0]))*prime64_2
				v1 = (p64<<31 | p64>>33) * prime64_1
				p64 = v2 + (uint64(sub[8+7])<<56|uint64(sub[8+6])<<48|uint64(sub[8+5])<<40|uint64(sub[8+4])<<32|uint64(sub[8+3])<<24|uint64(sub[8+2])<<16|uint64(sub[8+1])<<8|uint64(sub[8]))*prime64_2
				v2 = (p64<<31 | p64>>33) * prime64_1
				p64 = v3 + (uint64(sub[16+7])<<56|uint64(sub[16+6])<<48|uint64(sub[16+5])<<40|uint64(sub[16+4])<<32|uint64(sub[16+3])<<24|uint64(sub[16+2])<<16|uint64(sub[16+1])<<8|uint64(sub[16]))*prime64_2
				v3 = (p64<<31 | p64>>33) * prime64_1
				p64 = v4 + (uint64(sub[24+7])<<56|uint64(sub[24+6])<<48|uint64(sub[24+5])<<40|uint64(sub[24+4])<<32|uint64(sub[24+3])<<24|uint64(sub[24+2])<<16|uint64(sub[24+1])<<8|uint64(sub[24]))*prime64_2
				v4 = (p64<<31 | p64>>33) * prime64_1
			}
		}

		h64 = ((v1 << 1) | (v1 >> 63)) +
			((v2 << 7) | (v2 >> 57)) +
			((v3 << 12) | (v3 >> 52)) +
			((v4 << 18) | (v4 >> 46))

		v1 *= prime64_2
		h64 ^= ((v1 << 31) | (v1 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4

		v2 *= prime64_2
		h64 ^= ((v2 << 31) | (v2 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4

		v3 *= prime64_2
		h64 ^= ((v3 << 31) | (v3 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4

		v4 *= prime64_2
		h64 ^= ((v4 << 31) | (v4 >> 33)) * prime64_1
		h64 = h64*prime64_1 + prime64_4 + uint64(n)

		input = input[p:]
		n -= p
	} else {
		h64 = seed + prime64_5 + uint64(n)
	}

	if n == 0 {
		// Nothing to do
	} else if littleEndian {
		p := 0
		ptr := uintptr(unsafe.Pointer(&input[0]))
		for n := n - 8; p <= n; p += 8 {
			p64 := *(*uint64)(unsafe.Pointer(ptr)) * prime64_2
			h64 ^= ((p64 << 31) | (p64 >> 33)) * prime64_1
			h64 = ((h64<<27)|(h64>>37))*prime64_1 + prime64_4
			ptr += 8
		}
		if p+4 <= n {
			p32 := *(*uint32)(unsafe.Pointer(ptr))
			h64 ^= uint64(p32) * prime64_1
			h64 = ((h64<<23)|(h64>>41))*prime64_2 + prime64_3
			p += 4
			ptr += 4
		}
		for ; p < n; p++ {
			h64 ^= uint64(input[p]) * prime64_5
			h64 = ((h64 << 11) | (h64 >> 53)) * prime64_1
		}
	} else {
		p := 0
		for n := n - 8; p <= n; p += 8 {
			sub := input[p : p+8]
			p64 := (uint64(sub[7])<<56 | uint64(sub[6])<<48 | uint64(sub[5])<<40 | uint64(sub[4])<<32 | uint64(sub[3])<<24 | uint64(sub[2])<<16 | uint64(sub[1])<<8 | uint64(sub[0])) * prime64_2
			h64 ^= ((p64 << 31) | (p64 >> 33)) * prime64_1
			h64 = ((h64<<27)|(h64>>37))*prime64_1 + prime64_4
		}
		if p+4 <= n {
			sub := input[p : p+4]
			h64 ^= (uint64(sub[3])<<24 | uint64(sub[2])<<16 | uint64(sub[1])<<8 | uint64(sub[0])) * prime64_1
			h64 = ((h64<<23)|(h64>>41))*prime64_2 + prime64_3
			p += 4
		}
		for ; p < n; p++ {
			h64 ^= uint64(input[p]) * prime64_5
			h64 = ((h64 << 11) | (h64 >> 53)) * prime64_1
		}
	}

	h64 ^= h64 >> 33
	h64 *= prime64_2
	h64 ^= h64 >> 29
	h64 *= prime64_3
	h64 ^= h64 >> 32

	return h64
}
