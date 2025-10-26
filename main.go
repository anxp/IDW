package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"

	"github.com/anxp/bytecast"
	"golang.org/x/crypto/sha3"
)

const (
	rpcURL      = "https://arb1.arbitrum.io/rpc"
	poolAddress = "0xf3eb87c1f6020982173c908e7eb31aa66c1f0296"
)

// Lengths of hashes and addresses in bytes.
const (
	// HashLength is the expected length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 20
)

// =================================== ADDRESS TYPE (EXPORT TO SEP FILE) ===============================================

// Address represents the 20 byte address of an Ethereum account.
type Address [AddressLength]byte

// Bytes returns the raw 20 bytes of the address.
func (a *Address) Bytes() []byte {
	return a[:]
}

// Hex returns the hex string (with 0x prefix) representation of the address.
func (a *Address) Hex() string {
	return "0x" + hex.EncodeToString(a[:])
}

// String implements the Stringer interface (alias of Hex()).
func (a *Address) String() string {
	return a.Hex()
}

// Short returns a shortened version of the address for logging/debug output.
func (a *Address) Short() string {
	return fmt.Sprintf("0x%s...%s", hex.EncodeToString(a[:2]), hex.EncodeToString(a[18:]))
}

// IsZero returns true if the address is all zeros.
func (a *Address) IsZero() bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}

// SetBytes copies a 20-byte slice into the address (pads/truncates if needed).
func (a *Address) SetBytes(b []byte) {
	if len(b) > AddressLength {
		b = b[len(b)-AddressLength:] // truncate leading bytes
	}
	copy(a[AddressLength-len(b):], b)
}

// MustFromHex parses a hex string (with or without 0x) into an Address, panicking on error.
func MustFromHex(s string) Address {
	addr, err := FromHex(s)
	if err != nil {
		panic(err)
	}
	return addr
}

// FromHex parses a hex string into an Address.
func FromHex(s string) (Address, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Address{}, err
	}

	var a Address
	a.SetBytes(b)
	return a, nil
}

// =====================================================================================================================

// RPC request/response structures
type rpcRequest struct {
	Jsonrpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  string `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Slot0Response from UniswapV3 pool contract slot0() method should have the following structure:
//
// [ slot0 method Response ]
//
//	sqrtPriceX96              uint160 : 5042980585784787000000000
//	tick                        int24 : -193252
//	observationIndex           uint16 : 401
//	observationCardinality     uint16 : 1000
//	observationCardinalityNext uint16 : 1000
//	feeProtocol                 uint8 : 68
//	unlocked                     bool : true
type Slot0Response struct {
	SqrtPriceX96               *big.Int
	Tick                       int64
	ObservationIndex           uint16
	ObservationCardinality     uint16
	ObservationCardinalityNext uint16
	FeeProtocol                uint8
	Unlocked                   bool
}

// TicksResponse from UniswapV3 pool contract ticks(tick int24) method should have the following structure:
//
// [ ticks(int24) method Response ]
//
//	liquidityGross                 uint128 : 134482581265130
//	liquidityNet                    int128 : 134482581265130
//	feeGrowthOutside0X128          uint256 : 390565930168960973818863104680345990760075
//	feeGrowthOutside1X128          uint256 : 1052584084066102665588771223941227
//	tickCumulativeOutside            int56 : -13048615136924
//	secondsPerLiquidityOutsideX128 uint160 : 104138067329872268258331405011315
//	secondsOutside                  uint32 : 1754609140
//	initialized                       bool : true
type TicksResponse struct {
	LiquidityGross                 *big.Int
	LiquidityNet                   *big.Int
	FeeGrowthOutside0X128          *big.Int
	FeeGrowthOutside1X128          *big.Int
	TickCumulativeOutside          *big.Int
	SecondsPerLiquidityOutsideX128 *big.Int
	SecondsOutside                 uint32
	Initialized                    bool
}

func main() {
	addr := MustFromHex("0x82af49447d8a07e3bd95bd0d56f35241523fbab1")

	fmt.Println("Full:", addr.Hex())
	fmt.Println("Short:", addr.Short())
	fmt.Println("Bytes:", addr.Bytes())
	fmt.Println("IsZero:", addr.IsZero())

	var zero Address
	fmt.Println("Zero address check:", zero.IsZero())

	ticksResponse, err := contractMethodCall[TicksResponse](rpcURL, poolAddress, "ticks(int24)", int32(-193630))
	slot0Response, err := contractMethodCall[Slot0Response](rpcURL, poolAddress, "slot0()")
	token0Response, err := contractMethodCall[Address](rpcURL, poolAddress, "token0()")

	_, _, _, _ = ticksResponse, slot0Response, token0Response, err

	return
}

// contractMethodCall executes method/function "functionSignature" of contract "contractAddress" with input parameters "args" and returns result of type T.
//
//	Usage examples:
//		tickInfo, err := contractMethodCall[TickResponse](rpcURL, poolAddress, "ticks(int24)", int32(-193252))
//		slot0Response, err := contractMethodCall[Slot0Response](rpcURL, poolAddress, "slot0()")
//		token0Response, err := contractMethodCall[Address](rpcURL, poolAddress, "token0()")
func contractMethodCall[T any](rpcURL, contractAddress, functionSignature string, args ...interface{}) (*T, error) {
	// 1. Compute selector
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(functionSignature))
	fullHash := hash.Sum(nil)
	selector := fullHash[:4] // selector is first 4 bytes of signature hash
	data := append([]byte{}, selector...)

	// 2. Encode arguments
	for _, arg := range args {
		encoded, err := encodeValue(arg)
		if err != nil {
			return nil, err
		}
		data = append(data, encoded[:]...) // append 32 bytes
	}

	// 3. Prepare eth_call payload
	callObj := map[string]string{
		"to":   contractAddress,
		"data": "0x" + hex.EncodeToString(data),
	}

	reqBody := rpcRequest{
		Jsonrpc: "2.0",
		Method:  "eth_call",
		Params:  []interface{}{callObj, "latest"},
		ID:      1,
	}

	payload, _ := json.Marshal(reqBody)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var rpcResp rpcResponse
	if err = json.Unmarshal(body, &rpcResp); err != nil {
		return nil, err
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %v", rpcResp.Error.Message)
	}

	return parseHexResponse[T](rpcResp.Result)
}

// parseHexResponse parses eth_call response to structured data of type T.
//   - hexDataIn - input data as hex string
func parseHexResponse[T any](hexDataIn string) (*T, error) {

	if len(hexDataIn) >= 2 && hexDataIn[:2] == "0x" {
		hexDataIn = hexDataIn[2:]
	}

	if len(hexDataIn) < 64 { // 64 symbols in hex string = 32 bytes
		return nil, fmt.Errorf("input data too short")
	}

	data, err := hex.DecodeString(hexDataIn)
	if err != nil {
		return nil, fmt.Errorf("decoding hex input failed with error: %v", err)
	}

	if len(data)%32 != 0 {
		return nil, fmt.Errorf("response parse failed - byte data length is not a multiple of 32")
	}

	var result T
	expectedType := reflect.TypeOf(result)
	resultValue := reflect.ValueOf(&result).Elem()

	if expectedType.Kind() == reflect.Struct {
		numOfFields := resultValue.NumField()

		if len(data) < 32*numOfFields {
			return nil, fmt.Errorf("input data too short, expected at least %d bytes (32B x %d fields), got %d bytes instead", 32*numOfFields, numOfFields, len(data))
		}

		for i := 0; i < numOfFields; i++ {
			field := resultValue.Field(i)

			value, err := decodeValue(field.Type(), getFieldBytes(data, i))
			if err != nil {
				return nil, err
			}

			field.Set(value)
		}

		return &result, nil
	}

	value, err := decodeValue(expectedType, getFieldBytes(data, 0))
	if err != nil {
		return nil, err
	}

	resultValue.Set(value)
	return &result, nil
}

// getFieldBytes returns exactly 32 raw bytes of field #fieldNumber or panic.
func getFieldBytes(allData []byte, fieldNumber int) [32]byte {
	startByte := fieldNumber * 32
	endByte := startByte + 32
	fieldData := allData[startByte:endByte]

	// This case is theoretically impossible, so we do panic here, not return error.
	if len(fieldData) != 32 {
		panic(fmt.Sprintf("wrong input - expected field length = 32 bytes, got = %d bytes", len(fieldData)))
	}

	return [32]byte(fieldData)
}

func decodeValue(fieldType reflect.Type, bytes32 [32]byte) (reflect.Value, error) {

	switch fieldType {
	case reflect.TypeOf((*big.Int)(nil)):
		bigIntValue := bytecast.BigIntFromBytes(bytes32[:])
		return reflect.ValueOf(bigIntValue), nil

	case reflect.TypeOf(Address{}):
		addressValue := Address(bytes32[12:32])
		return reflect.ValueOf(addressValue), nil

	case reflect.TypeOf(int64(0)):
		int64Value := bytecast.Int64From8Bytes([8]byte(bytes32[24:]))
		return reflect.ValueOf(int64Value), nil

	case reflect.TypeOf(int32(0)):
		int32Value := bytecast.Int32From4Bytes([4]byte(bytes32[28:]))
		return reflect.ValueOf(int32Value), nil

	case reflect.TypeOf(uint32(0)):
		uint32Value := bytecast.Uint32From4Bytes([4]byte(bytes32[28:]))
		return reflect.ValueOf(uint32Value), nil

	case reflect.TypeOf(uint16(0)):
		uint16Value := bytecast.Uint16From2Bytes([2]byte(bytes32[30:]))
		return reflect.ValueOf(uint16Value), nil

	case reflect.TypeOf(uint8(0)):
		uint8Value := bytecast.Uint8From1Byte([1]byte(bytes32[31:]))
		return reflect.ValueOf(uint8Value), nil

	case reflect.TypeOf(false):
		boolValue := bytecast.BoolFrom1Byte([1]byte(bytes32[31:]))
		return reflect.ValueOf(boolValue), nil
	}

	return reflect.Value{}, fmt.Errorf("failed to decode bytes - unsupported type: %v", fieldType)
}

func encodeValue(value interface{}) ([32]byte, error) {
	var encodedValue []byte
	var err error

	switch value.(type) {
	case *big.Int:
		encodedValue, err = bytecast.BigIntToBytesAndExpandWidth(value.(*big.Int), 32)

	case Address:
		encodedValue = bytecast.LeftPadBytes00(value.([]byte), 32)

	case int64:
		encodedValue, err = bytecast.Int64ToBytesAndExpandWidth(value.(int64), 32)

	case int32:
		encodedValue, err = bytecast.Int32ToBytesAndExpandWidth(value.(int32), 32)

	case uint32:
		encodedValue, err = bytecast.Uint32ToBytesAndExpandWidth(value.(uint32), 32)

	case uint16:
		encodedValue, err = bytecast.Uint16ToBytesAndExpandWidth(value.(uint16), 32)

	case uint8:
		encodedValue, err = bytecast.Uint8ToBytesAndExpandWidth(value.(uint8), 32)

	case bool:
		encodedValue, err = bytecast.BoolToBytesAndExpandWidth(value.(bool), 32)

	default:
		err = fmt.Errorf("failed to encode typed value to 32B field - unsupported argument type: %T", value)
	}

	if err != nil {
		return [32]byte{}, err
	}

	return [32]byte(encodedValue), nil
}
