package xxHash32_test

import (
	"github.com/pierrec/xxHash/xxHash32"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"
	"testing"
)

///////////////////////////////////////////////////////////////////////////////
// Tests
//
// with small input multiple of 4
func TestXXHSmallInput4(t *testing.T) {
	var data = []byte("abcd")

	var xxh = xxHash32.New(0)
	xxh.Write(data)

	expected := uint32(0xa3643705)
	if h := xxh.Sum32(); h != expected {
		t.Errorf("TestXXHSmallInput4: %x", h)
	}
	if h := xxHash32.Checksum(data, 0); h != expected {
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
	var xxh = xxHash32.New(0)
	xxh.Write(data)

	expected := uint32(0xe18cbea)
	if h := xxh.Sum32(); h != expected {
		t.Errorf("TestXXHMediumInput4: %x", h)
	}
	if h := xxHash32.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHMediumInput4: %x", h)
	}
}

// with small input
func TestXXHSmallInput(t *testing.T) {
	var data = []byte("abc")

	var xxh = xxHash32.New(0)
	xxh.Write(data)

	expected := uint32(0x32d153ff)
	if h := xxh.Sum32(); h != expected {
		t.Errorf("TestXXHSmallInput: %x", h)
	}
	if h := xxHash32.Checksum(data, 0); h != expected {
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
	var xxh = xxHash32.New(0)
	xxh.Write(data)

	expected := uint32(0x89da9b6e)
	if h := xxh.Sum32(); h != expected {
		t.Errorf("TestXXHMediumInput: %x", h)
	}
	if h := xxHash32.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHMediumInput: %x", h)
	}
}

// with split medium input <16
func TestXXHSplitMediumInputLt16(t *testing.T) {
	var dataSample = []byte("abc")
	var data []byte

	for i := 0; i < 999; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash32.New(0)
	xxh.Write(data[0:10])
	xxh.Write(data[10:])

	expected := uint32(0x89da9b6e)
	if h := xxh.Sum32(); h != expected {
		t.Errorf("TestXXHSplitMediumInputLt16: %x", h)
	}
	if h := xxHash32.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSplitMediumInputLt16: %x", h)
	}
}

// with split medium input ==16
func TestXXHSplitMediumInputEq16(t *testing.T) {
	var dataSample = []byte("abc")
	var data []byte

	for i := 0; i < 999; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash32.New(0)
	xxh.Write(data[0:16])
	xxh.Write(data[16:])

	expected := uint32(0x89da9b6e)
	if h := xxh.Sum32(); h != expected {
		t.Errorf("TestXXHSplitMediumInputEq16: %x", h)
	}
	if h := xxHash32.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSplitMediumInputEq16: %x", h)
	}
}

// with split medium input >16
func TestXXHSplitMediumInputGt16(t *testing.T) {
	var dataSample = []byte("abc")
	var data []byte

	for i := 0; i < 999; i++ {
		data = append(data, dataSample...)
	}
	var xxh = xxHash32.New(0)
	xxh.Write(data[0:20])
	xxh.Write(data[20:])

	expected := uint32(0x89da9b6e)
	if h := xxh.Sum32(); h != expected {
		t.Errorf("TestXXHSplitMediumInputGt16: %x", h)
	}
	if h := xxHash32.Checksum(data, 0); h != expected {
		t.Errorf("TestXXHSplitMediumInputGt16: %x", h)
	}
}

///////////////////////////////////////////////////////////////////////////////
// Benchmarks
//
var testdata1 = []byte("Lorem ipsum dolor sit amet, consectetuer adipiscing elit, ")

func Benchmark_XXH32(b *testing.B) {
	h := xxHash32.New(0)
	for n := 0; n < b.N; n++ {
		h.Write(testdata1)
		h.Sum32()
		h.Reset()
	}
}

func Benchmark_XXH32_Checksum(b *testing.B) {
	for n := 0; n < b.N; n++ {
		xxHash32.Checksum(testdata1, 0)
	}
}

func Benchmark_CRC32IEEE(b *testing.B) {
	for i := 0; i < b.N; i++ {
		crc32.ChecksumIEEE(testdata1)
	}
}

func Benchmark_Adler32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		adler32.Checksum(testdata1)
	}
}

func Benchmark_Fnv32(b *testing.B) {
	h := fnv.New32()
	for i := 0; i < b.N; i++ {
		h.Write(testdata1)
		h.Sum32()
		h.Reset()
	}
}
