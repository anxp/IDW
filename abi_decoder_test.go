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

func TestDecodeSwapEvent(t *testing.T) {
	// Real event taken from: https://arbiscan.io/tx/0x8554f3c1ce4d3e02b5ac3ff4b468acb1d1f02226754ac37f1ec0a2b6bec7840f#eventlog

	logRecord := Log{
		Address: MustFromHex("0xD1E1Ac29B31B35646EaBD77163E212b76fE3b6A2"),
		Topics: []string{
			"0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67",
			"0x000000000000000000000000f2614a233c7c3e7f08b1f887ba133a13f1eb2c55",
			"0x00000000000000000000000061952de125ec80adea67b3b44727cf45f206e20d",
		},
		Data:             "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffe748f85a0000000000000000000000000000000000000000000000000000000018bc62ba00000000000000000000000000000000000000010018d1b40a04d0c2fcb3e1ea000000000000000000000000000000000000000000000000000021d620ba43a40000000000000000000000000000000000000000000000000000000000000007",
		TransactionIndex: 0,
		LogIndex:         0,
	}

	// ABI description of event:
	swapEvent := ABIEvent{
		Name: "Swap",
		Params: []ABIEventParam{
			{Name: "sender", Type: ABIAddress, Indexed: true},
			{Name: "recipient", Type: ABIAddress, Indexed: true},
			{Name: "amount0", Type: ABIInt256, Indexed: false},
			{Name: "amount1", Type: ABIInt256, Indexed: false},
			{Name: "sqrtPriceX96", Type: ABIUint160, Indexed: false},
			{Name: "liquidity", Type: ABIUint128, Indexed: false},
			{Name: "tick", Type: ABIInt24, Indexed: false},
		},
	}

	eventDecoded, err := DecodeEvent(logRecord, swapEvent)
	if err != nil {
		t.Fatalf("Failed to decode example of swap event: %v", err)
	}

	senderAddress := eventDecoded.Fields["sender"].(Address)
	senderAddressExpected := MustFromHex("0xf2614A233c7C3e7f08b1F887Ba133a13f1eb2c55")

	t.Logf("Decoded sender: %s", &senderAddress)
	t.Logf("Expected:       %s", &senderAddressExpected)

	if senderAddress != senderAddressExpected {
		t.Errorf("Decoded SENDER does not match expected!\nGot:  %s\nWant: %s", &senderAddress, &senderAddressExpected)
	}

	recipientAddress := eventDecoded.Fields["recipient"].(Address)
	recipientAddressExpected := MustFromHex("0x61952DE125Ec80ADEA67B3B44727CF45F206E20d")

	t.Logf("Decoded recipient: %s", &recipientAddress)
	t.Logf("Expected:          %s", &recipientAddressExpected)

	if recipientAddress != recipientAddressExpected {
		t.Errorf("Decoded RECIPIENT does not match expected!\nGot:  %s\nWant: %s", &recipientAddress, &recipientAddressExpected)
	}

	amount0 := eventDecoded.Fields["amount0"].(*big.Int)
	amount0Expected := big.NewInt(-414648230)

	t.Logf("Decoded amount0: %s", amount0)
	t.Logf("Expected:        %s", amount0Expected)

	if amount0.Cmp(amount0Expected) != 0 {
		t.Errorf("Decoded AMOUNT0 does not match expected!\nGot:  %s\nWant: %s", amount0, amount0Expected)
	}

	amount1 := eventDecoded.Fields["amount1"].(*big.Int)
	amount1Expected := big.NewInt(414999226)

	t.Logf("Decoded amount1: %s", amount1)
	t.Logf("Expected:        %s", amount1Expected)

	if amount1.Cmp(amount1Expected) != 0 {
		t.Errorf("Decoded AMOUNT1 does not match expected!\nGot:  %s\nWant: %s", amount1, amount1Expected)
	}

	sqrtPriceX96 := eventDecoded.Fields["sqrtPriceX96"].(*big.Int)
	sqrtPriceX96Expected, _ := big.NewInt(0).SetString("79258167029665873093473853930", 10)

	t.Logf("Decoded sqrtPriceX96: %s", sqrtPriceX96)
	t.Logf("Expected:             %s", sqrtPriceX96Expected)

	if sqrtPriceX96.Cmp(sqrtPriceX96Expected) != 0 {
		t.Errorf("Decoded SQRTPRICEX96 does not match expected!\nGot:  %s\nWant: %s", sqrtPriceX96, sqrtPriceX96Expected)
	}

	liquidity := eventDecoded.Fields["liquidity"].(*big.Int)
	liquidityExpected, _ := big.NewInt(0).SetString("37203555795876", 10)

	t.Logf("Decoded liquidity: %s", liquidity)
	t.Logf("Expected:          %s", liquidityExpected)

	if liquidity.Cmp(liquidityExpected) != 0 {
		t.Errorf("Decoded LIQUIDITY does not match expected!\nGot:  %s\nWant: %s", liquidity, liquidityExpected)
	}

	tick := eventDecoded.Fields["tick"].(int32)
	tickExpected := int32(7)

	t.Logf("Decoded tick: %d", tick)
	t.Logf("Expected:     %d", tickExpected)

	if tick != tickExpected {
		t.Errorf("Decoded TICK does not match expected!\nGot:  %d\nWant: %d", tick, tickExpected)
	}
}
