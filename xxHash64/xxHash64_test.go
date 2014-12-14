package xxHash64_test

import (
	"github.com/pierrec/xxHash/xxHash64"
	"hash/crc64"
	"hash/fnv"
	"testing"
)

///////////////////////////////////////////////////////////////////////////////
// Tests
//
// with small input multiple of 4
func TestXXHSmallInput4(t *testing.T) {
	var data = []byte("abcd")

	var xxh = xxHash64.New(0)
	xxh.Write(data)

	expected := uint64(0xde0327b0d25d92cc)
	if h := xxh.Sum64(); h != expected {
		t.Errorf("TestXXHSmallInput4: %x", h)
	}
	if h := xxHash64.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSmallInput4: %x", h)
	}
}

// with medium input multiple of 4
func TestXXHMediumInput4(t *testing.T) {
	var dataSample = []byte("abcd")
	var data []byte

	for i := 0; i < 1000; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash64.New(0)
	xxh.Write(data)

	expected := uint64(0x205219d38e8898bc)
	if h := xxh.Sum64(); h != expected {
		t.Errorf("TestXXHSmallInput4: %x", h)
	}
	if h := xxHash64.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSmallInput4: %x", h)
	}
}

// with small input
func TestXXHSmallInput(t *testing.T) {
	var data = []byte("abc")

	var xxh = xxHash64.New(0)
	xxh.Write(data)

	expected := uint64(0x44bc2cf5ad770999)
	if h := xxh.Sum64(); h != expected {
		t.Errorf("TestXXHSmallInput: %x", h)
	}
	if h := xxHash64.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSmallInput: %x", h)
	}
}

// with medium input
func TestXXHMediumInput(t *testing.T) {
	var dataSample = []byte("abc")
	var data []byte

	for i := 0; i < 999; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash64.New(0)
	xxh.Write(data)

	expected := uint64(0x933eb85613976467)
	if h := xxh.Sum64(); h != expected {
		t.Errorf("TestXXHMediumInput: %x", h)
	}
	if h := xxHash64.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHMediumInput: %x", h)
	}
}

// with split medium input <32
func TestXXHSplitMediumInputLt32(t *testing.T) {
	var dataSample = []byte("abc")
	var data []byte

	for i := 0; i < 999; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash64.New(0)
	xxh.Write(data[0:20])
	xxh.Write(data[20:])

	expected := uint64(0x933eb85613976467)
	if h := xxh.Sum64(); h != expected {
		t.Errorf("TestXXHSplitMediumInputLt32: %x", h)
	}
	if h := xxHash64.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSplitMediumInputLt32: %x", h)
	}
}

// with split medium input ==32
func TestXXHSplitMediumInputEq32(t *testing.T) {
	var dataSample = []byte("abc")
	var data []byte

	for i := 0; i < 999; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash64.New(0)
	xxh.Write(data[0:32])
	xxh.Write(data[32:])

	expected := uint64(0x933eb85613976467)
	if h := xxh.Sum64(); h != expected {
		t.Errorf("TestXXHSplitMediumInputEq32: %x", h)
	}
	if h := xxHash64.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSplitMediumInputEq32: %x", h)
	}
}

// with split medium input >32
func TestXXHSplitMediumInputGt32(t *testing.T) {
	var dataSample = []byte("abc")
	var data []byte

	for i := 0; i < 999; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash64.New(0)
	xxh.Write(data[0:40])
	xxh.Write(data[40:])

	expected := uint64(0x933eb85613976467)
	if h := xxh.Sum64(); h != expected {
		t.Errorf("TestXXHSplitMediumInputGt32: %x", h)
	}
	if h := xxHash64.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSplitMediumInputGt32: %x", h)
	}
}

///////////////////////////////////////////////////////////////////////////////
// Benchmarks
//
var testdata1 = []byte("Lorem ipsum dolor sit amet, consectetuer adipiscing elit, ")

func Benchmark_XXH64(b *testing.B) {
	h := xxHash64.New(0)
	for n := 0; n < b.N; n++ {
		h.Write(testdata1)
		h.Sum64()
		h.Reset()
	}
}

func Benchmark_XXH64_Checksum(b *testing.B) {
	for n := 0; n < b.N; n++ {
		xxHash64.Checksum(testdata1, 0)
	}
}

func Benchmark_CRC64(b *testing.B) {
	t := crc64.MakeTable(0)
	for i := 0; i < b.N; i++ {
		crc64.Checksum(testdata1, t)
	}
}

func Benchmark_Fnv64(b *testing.B) {
	h := fnv.New64()
	for i := 0; i < b.N; i++ {
		h.Write(testdata1)
		h.Sum64()
		h.Reset()
	}
}
