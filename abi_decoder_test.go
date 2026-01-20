package main

import (
	"math/big"
	"testing"
)

func TestDecodeApproveEvent(t *testing.T) {
	// Real event taken from: https://arbiscan.io/tx/0x17e56b7c53113bf24e670f5fe42c2551f227088a1c34b5ae6d342adbd474f9b2#eventlog

	logRecord := Log{
		Address: MustFromHex("0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
		Topics: []string{
			"0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
			"0x00000000000000000000000035976f39bce40ce858fb66360c49231e6b8ee4a1",
			"0x000000000000000000000000f2614a233c7c3e7f08b1f887ba133a13f1eb2c55",
		},
		Data:             "0x00000000000000000000000000000000000000000000000000000000000f4240",
		TransactionIndex: 0,
		LogIndex:         0,
	}

	// ABI description of event:
	approvalEvent := ABIEvent{
		Name: "Approval",
		Params: []ABIEventParam{
			{Name: "owner", Type: ABIAddress, Indexed: true},
			{Name: "spender", Type: ABIAddress, Indexed: true},
			{Name: "value", Type: ABIUint256, Indexed: false},
		},
	}

	eventDecoded, err := DecodeEvent(logRecord, approvalEvent)
	if err != nil {
		t.Fatalf("Failed to decode example of approval event: %v", err)
	}

	ownerAddress := eventDecoded.Fields["owner"].(Address)
	ownerAddressExpected := MustFromHex("0x35976f39BCe40Ce858fB66360c49231E6B8Ee4A1")

	t.Logf("Decoded owner: %s", &ownerAddress)
	t.Logf("Expected:      %s", &ownerAddressExpected)

	if ownerAddress != ownerAddressExpected {
		t.Errorf("Decoded OWNER does not match expected!\nGot:  %s\nWant: %s", &ownerAddress, &ownerAddressExpected)
	}

	spenderAddress := eventDecoded.Fields["spender"].(Address)
	spenderAddressExpected := MustFromHex("0xf2614A233c7C3e7f08b1F887Ba133a13f1eb2c55")

	t.Logf("Decoded spender: %s", &spenderAddress)
	t.Logf("Expected:        %s", &spenderAddressExpected)

	if spenderAddress != spenderAddressExpected {
		t.Errorf("Decoded SPENDER does not match expected!\nGot:  %s\nWant: %s", &spenderAddress, &spenderAddressExpected)
	}

	value := eventDecoded.Fields["value"].(*big.Int)
	valueExpected := big.NewInt(1000000)

	t.Logf("Decoded value: %s", value)
	t.Logf("Expected:      %s", valueExpected)

	if value.Cmp(valueExpected) != 0 {
		t.Errorf("Decoded VALUE does not match expected!\nGot:  %s\nWant: %s", value, valueExpected)
	}
}
