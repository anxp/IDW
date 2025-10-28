package main

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// TestRLPEncodeString checks if RLPEncode correctly encodes text string
func TestRLPEncodeString(t *testing.T) {
	stringValue := "dog"

	encoded, err := RLPEncode(stringValue)
	if err != nil {
		t.Fatalf("RLP encode failed: %v", err)
	}

	expectedHex := "83646f67" // [ 0x83, 'd', 'o', 'g' ]

	gotHex := hex.EncodeToString(encoded[:])

	t.Logf("Encoded:   %s", gotHex)
	t.Logf("Expected:  %s", expectedHex)

	if gotHex != expectedHex {
		t.Errorf("Encoded does not match expected!\nGot:  %s\nWant: %s", gotHex, expectedHex)
	}
}

// TestRLPEncodeString checks if RLPEncode correctly encodes list of values
func TestRLPEncodeList(t *testing.T) {
	encoder := func(subject []string, expected string) {
		encoded, err := RLPEncode(subject)
		if err != nil {
			t.Fatalf("RLP encode failed: %v", err)
		}

		gotHex := hex.EncodeToString(encoded[:])

		t.Logf("Encoded:   %s", gotHex)
		t.Logf("Expected:  %s", expected)

		if gotHex != expected {
			t.Errorf("Encoded does not match expected!\nGot:  %s\nWant: %s", gotHex, expected)
		}
	}

	encoder([]string{"cat", "dog"}, "c88363617483646f67")
	encoder([]string{}, "c0")
}

// TestRLPEncodeString checks if RLPEncode correctly encodes bytes slice
func TestRLPEncodeByteSlice(t *testing.T) {
	encoder := func(subject []byte, expected string) {
		encoded, err := RLPEncode(subject)
		if err != nil {
			t.Fatalf("RLP encode failed: %v", err)
		}

		gotHex := hex.EncodeToString(encoded[:])

		t.Logf("Encoded:   %s", gotHex)
		t.Logf("Expected:  %s", expected)

		if gotHex != expected {
			t.Errorf("Encoded does not match expected!\nGot:  %s\nWant: %s", gotHex, expected)
		}
	}

	encoder([]byte{0x04, 0x00}, "820400")
	encoder([]byte{}, "80")
}

// TestRLPEncodeUint64 checks if RLPEncode correctly encodes uint64
func TestRLPEncodeUint64(t *testing.T) {
	encoder := func(subject uint64, expected string) {
		encoded, err := RLPEncode(subject)
		if err != nil {
			t.Fatalf("RLP encode failed: %v", err)
		}

		gotHex := hex.EncodeToString(encoded[:])

		t.Logf("Encoded:   %s", gotHex)
		t.Logf("Expected:  %s", expected)

		if gotHex != expected {
			t.Errorf("Encoded does not match expected!\nGot:  %s\nWant: %s", gotHex, expected)
		}
	}

	encoder(777, "820309")
	encoder(0, "80")
}

// TestRLPEncodeByte checks if RLPEncode correctly encodes 1 byte value
func TestRLPEncodeByte(t *testing.T) {
	encoder := func(subject byte, expected string) {
		encoded, err := RLPEncode(subject)
		if err != nil {
			t.Fatalf("RLP encode failed: %v", err)
		}

		gotHex := hex.EncodeToString(encoded[:])

		t.Logf("Encoded:   %s", gotHex)
		t.Logf("Expected:  %s", expected)

		if gotHex != expected {
			t.Errorf("Encoded does not match expected!\nGot:  %s\nWant: %s", gotHex, expected)
		}
	}

	encoder(0x00, "00")
	encoder(0x7f, "7f")
	encoder(0x0f, "0f")
	encoder(0x80, "8180")
}

// TestRLPEncodeBigInt checks if RLPEncode correctly encodes big int value
func TestRLPEncodeBigInt(t *testing.T) {
	encoder := func(subject *big.Int, expected string) {
		encoded, err := RLPEncode(subject)

		if err != nil {
			t.Fatalf("RLP encode failed: %v", err)
		}

		gotHex := hex.EncodeToString(encoded[:])

		t.Logf("Encoded:   %s", gotHex)
		t.Logf("Expected:  %s", expected)

		if gotHex != expected {
			t.Errorf("Encoded does not match expected!\nGot:  %s\nWant: %s", gotHex, expected)
		}
	}

	encoder(big.NewInt(127), "7f")
	encoder(big.NewInt(128), "8180")
	encoder((*big.Int)(nil), "80")
}

func TestRLPEncodeNestedList(t *testing.T) {
	nestedList := [][]string{{"cat", "dog"}, {"cow"}}

	encoded, err := RLPEncode(nestedList)

	if err != nil {
		t.Fatalf("RLP encode failed: %v", err)
	}

	expected := "cec88363617483646f67c483636f77"
	gotHex := hex.EncodeToString(encoded)

	t.Logf("Encoded:   %s", gotHex)
	t.Logf("Expected:  %s", expected)

	if gotHex != expected {
		t.Errorf("Got %s, want %s", gotHex, expected)
	}
}
