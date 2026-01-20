package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/anxp/bytecast"
	"golang.org/x/crypto/sha3"
)

const (
	rpcURLArbitrum = "https://arb1.arbitrum.io/rpc"
	rpcURLBSC      = "https://bsc.drpc.org"
	poolAddress    = "0xf3eb87c1f6020982173c908e7eb31aa66c1f0296"
)

// =================================== ADDRESS TYPE (EXPORT TO SEP FILE) ===============================================

const AddressLength = 20

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
	addr, err := AddressFromHex(s)
	if err != nil {
		panic(err)
	}
	return addr
}

// AddressFromHex parses a hex string into an Address.
func AddressFromHex(s string) (Address, error) {
	hexValue := strings.TrimPrefix(s, "0x")

	b, err := hex.DecodeString(hexValue)
	if err != nil {
		return Address{}, err
	}

	if len(b) != AddressLength {
		return Address{}, errors.New("failed to decode address, invalid input")
	}

	var a Address
	copy(a[:], b)

	return a, nil
}

// =====================================================================================================================

// =================================== HASH TYPE (EXPORT TO SEP FILE) ==================================================

const HashLength = 32

type Hash [HashLength]byte

// Hex returns the hex string (with 0x prefix) representation of the address.
func (h Hash) Hex() string {
	return "0x" + hex.EncodeToString(h[:])
}

// String implements the Stringer interface (alias of Hex()).
func (h Hash) String() string {
	return h.Hex()
}

// Short returns a shortened version of the address for logging/debug output.
func (h Hash) Short() string {
	return fmt.Sprintf("0x%s...%s", hex.EncodeToString(h[:2]), hex.EncodeToString(h[18:]))
}

func HashFromHex(s string) (Hash, error) {
	hexValue := strings.TrimPrefix(s, "0x")

	b, err := hex.DecodeString(hexValue)
	if err != nil {
		return Hash{}, err
	}

	if len(b) != HashLength {
		return Hash{}, errors.New("failed to decode hash, invalid input")
	}

	var hash Hash
	copy(hash[:], b)

	return hash, nil
}

// =====================================================================================================================

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

	secp256k1 := InitSECP256K1Curve()
	privateKey, err := LoadPrivateKey("PRIVATE KEY HERE", secp256k1)
	if err != nil {
		log.Fatal(err)
	}

	from := MustFromHex("0x35976f39BCe40Ce858fB66360c49231E6B8Ee4A1")            // address of my wallet
	arbSushiRouter5 := MustFromHex("0xf2614A233c7C3e7f08b1F887Ba133a13f1eb2c55") // router, the contract who actually does swap
	arbUsdcContract := MustFromHex("0xaf88d065e77c8cC2239327C5EDb3A432268e5831") // contract of USDC token deployed in Arbitrum
	arbChainID := big.NewInt(42161)
	amountUSDC6Dec := big.NewInt(1000000) // amount, 1 usdc

	from = MustFromHex("0x35976f39BCe40Ce858fB66360c49231E6B8Ee4A1")             // address of my wallet
	bscSushiRouter4 := MustFromHex("0x33d91116e0370970444B0281AB117e161fEbFcdD") // router, the contract who actually does swap
	bscUsdcContract := MustFromHex("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d") // contract of USDC token deployed in Arbitrum
	bscChainID := big.NewInt(56)
	amountUSDC18Dec := big.NewInt(1000000000000000000) // amount, 1 usdc

	_, _, _, _ = arbSushiRouter5, arbUsdcContract, amountUSDC6Dec, arbChainID

	approveData, err := EncodeContractPayload("approve(address,uint256)", bscSushiRouter4, amountUSDC18Dec)
	if err != nil {
		log.Fatal(err)
	}

	gas, err := GetGasParams(rpcURLBSC, from, bscUsdcContract, approveData, big.NewInt(0))
	if err != nil {
		log.Fatal(err)
	}

	txHash, err := ExecuteTx(rpcURLBSC, privateKey, &bscUsdcContract, bscChainID, gas, big.NewInt(0), approveData)
	if err != nil {
		log.Fatal(err)
	}

	_ = txHash

	receipt, err := WaitTransactionReady(rpcURLBSC, txHash)
	if err != nil {
		log.Fatal(err)
	}

	_ = receipt

	ticksResponse, err := ContractMethodCall[TicksResponse](rpcURLArbitrum, poolAddress, "ticks(int24)", int32(-193630))
	slot0Response, err := ContractMethodCall[Slot0Response](rpcURLArbitrum, poolAddress, "slot0()")
	token0Response, err := ContractMethodCall[Address](rpcURLArbitrum, poolAddress, "token0()")

	_, _, _, _ = ticksResponse, slot0Response, token0Response, err

	return
}

// ContractMethodCall executes method "functionSignature" of contract "contractAddress" with input parameters "args" and returns result of type T.
//
//	[READONLY] This is NOT-state-changing call
//	>>> See ExecuteTx for state-changing call
//
//	Usage examples:
//		tickInfo, err := ContractMethodCall[TickResponse](rpcURL, poolAddress, "ticks(int24)", int32(-193252))
//		slot0Response, err := ContractMethodCall[Slot0Response](rpcURL, poolAddress, "slot0()")
//		token0Response, err := ContractMethodCall[Address](rpcURL, poolAddress, "token0()")
func ContractMethodCall[T any](rpcURL, contractAddress, functionSignature string, args ...interface{}) (*T, error) {
	data, err := EncodeContractPayload(functionSignature, args...)
	if err != nil {
		return nil, err
	}

	// Prepare eth_call payload
	callObj := map[string]string{
		"to":   contractAddress,
		"data": "0x" + hex.EncodeToString(data),
	}

	// Strictly said, we don't receive json as answer here, we get just a hex-encoded string, like:
	//	0x
	//	00000000000000000000000000000000000000000000000000007a4faa7c1aea
	//	00000000000000000000000000000000000000000000000000007a4faa7c1aea
	//	0000000000000000000000000000005996939631bcd88de114095b9a9826ca4d
	//	000000000000000000000000000000000000066d558f8dc0b8fbfcb7863fb10f
	//	fffffffffffffffffffffffffffffffffffffffffffffffffffffebc9c4462a8
	//	00000000000000000000000000000000000000007b1502a2e910685f249c514b
	//	00000000000000000000000000000000000000000000000000000000006e00db
	//	0000000000000000000000000000000000000000000000000000000000000001
	rawJson, err := ethereumMethodCall(rpcURL, "eth_call", []interface{}{callObj, "latest"})
	if err != nil {
		return nil, fmt.Errorf("failed to call eth_call: %v", err)
	}

	// Consequently, we parse "json" response directly in string-type variable:
	var hexResult string
	if err = json.Unmarshal(rawJson, &hexResult); err != nil {
		return nil, err
	}

	return parseHexResponse[T](hexResult)
}

// ExecuteTx executes transaction and returns transaction hash.
//
//	[WRITE] This IS state-changing call
//	>>> See ContractMethodCall for NOT-state-changing call
//
//	Use EncodeContractPayload() method to encode data parameter.
func ExecuteTx(rpcURL string, privateKey *ecdsa.PrivateKey, to *Address, chainID *big.Int, gas GasParams, value *big.Int, data []byte) (txHash *Hash, err error) {
	from := GetAddressFromPrivateKey(privateKey)

	nonce, err := GetNonce(from, rpcURL)
	if err != nil {
		return nil, err
	}

	if gas.Type == 2 {
		rawTx1559, err := buildRawTransaction1559(chainID, nonce, to, gas, value, data)
		if err != nil {
			return nil, err
		}

		txRawRlpEncoded, err := rlpEncodeTransaction1559ForSigning(rawTx1559)
		if err != nil {
			return nil, err
		}

		txRawHash := hashTransaction(txRawRlpEncoded)

		secp256k1 := InitSECP256K1Curve()

		v, r, s, err := Sign1559Hash(txRawHash, privateKey, secp256k1)
		if err != nil {
			return nil, err
		}

		rawTx1559.V = v
		rawTx1559.R = r
		rawTx1559.S = s

		txSignedRlpEncoded, err := rlpEncodeTransaction1559AfterSigning(rawTx1559)
		if err != nil {
			return nil, err
		}

		txHex := "0x" + hex.EncodeToString(txSignedRlpEncoded)

		rawJson, err := ethereumMethodCall(rpcURL, "eth_sendRawTransaction", []interface{}{txHex})
		if err != nil {
			return nil, err
		}

		txHashString := ""
		if err = json.Unmarshal(rawJson, &txHashString); err != nil {
			return nil, err
		}

		txHashObject, err := HashFromHex(txHashString)
		if err != nil {
			return nil, err
		}

		return &txHashObject, nil

	} else if gas.Type == 0 {
		rawTxLegacy, err := buildRawTransactionLegacy(nonce, to, gas, value, data)
		if err != nil {
			return nil, err
		}

		txRawRlpEncoded, err := rlpEncodeTransactionLegacyForSigning(rawTxLegacy, chainID)
		if err != nil {
			return nil, err
		}

		txRawHash := hashTransaction(txRawRlpEncoded)

		secp256k1 := InitSECP256K1Curve()

		// We can reuse EIP1559 signer, but don't forget we should upgrade "v" after signing (according to EIP-155)!
		v, r, s, err := Sign1559Hash(txRawHash, privateKey, secp256k1)
		if err != nil {
			return nil, err
		}

		// v = recID + 35 + 2*chainId
		v.Add(v, big.NewInt(35)).Add(v, big.NewInt(0).Mul(chainID, big.NewInt(2)))

		rawTxLegacy.V = v
		rawTxLegacy.R = r
		rawTxLegacy.S = s

		txSignedRlpEncoded, err := rlpEncodeTransactionLegacyAfterSigning(rawTxLegacy)
		if err != nil {
			return nil, err
		}

		txHex := "0x" + hex.EncodeToString(txSignedRlpEncoded)

		rawJson, err := ethereumMethodCall(rpcURL, "eth_sendRawTransaction", []interface{}{txHex})
		if err != nil {
			return nil, err
		}

		txHashString := ""
		if err = json.Unmarshal(rawJson, &txHashString); err != nil {
			return nil, err
		}

		txHashObject, err := HashFromHex(txHashString)
		if err != nil {
			return nil, err
		}

		return &txHashObject, nil
	} else {
		panic("this transaction type not yet implemented")
	}
}

func WaitTransactionReady(rpcURL string, txHash *Hash) (*TransactionReceipt, error) {
	for i := 0; i < 120; i++ {
		receipt, err := GetTransactionReceipt(rpcURL, txHash)
		if err != nil {
			return nil, err
		}

		if receipt != nil {
			if receipt.Status == 0 {
				return nil, fmt.Errorf("transaction reverted")
			}

			return receipt, nil
		}
		time.Sleep(1 * time.Second)
	}

	return nil, fmt.Errorf("waiting for transaction timed out")
}

func GetTransactionReceipt(rpcURL string, txHash *Hash) (*TransactionReceipt, error) {
	type rpcReceipt struct {
		Type              string `json:"type"`
		Status            string `json:"status"`
		CumulativeGasUsed string `json:"cumulativeGasUsed"`
		Logs              []struct {
			Address          string   `json:"address"`
			Topics           []string `json:"topics"`
			Data             string   `json:"data"`
			TransactionIndex string   `json:"transactionIndex"`
			LogIndex         string   `json:"logIndex"`
		} `json:"logs"`
		TransactionHash   string `json:"transactionHash"`
		TransactionIndex  string `json:"transactionIndex"`
		BlockHash         string `json:"blockHash"`
		BlockNumber       string `json:"blockNumber"`
		GasUsed           string `json:"gasUsed"`
		EffectiveGasPrice string `json:"effectiveGasPrice"`
		From              string `json:"from"`
		To                string `json:"to"`

		ContractAddress string `json:"contractAddress"`
	}

	rawJson, err := ethereumMethodCall(rpcURL, "eth_getTransactionReceipt", []interface{}{(*txHash).String()})
	if err != nil {
		return nil, err
	}

	// Якщо транзакція ще не замайнена — RPC повертає null
	if string(rawJson) == "null" {
		return nil, nil
	}

	var raw rpcReceipt
	if err := json.Unmarshal(rawJson, &raw); err != nil {
		return nil, err
	}

	txType, err := strconv.ParseInt(strings.TrimPrefix(raw.Type, "0x"), 16, 64)
	if err != nil {
		return nil, err
	}

	status, err := strconv.ParseInt(strings.TrimPrefix(raw.Status, "0x"), 16, 64)
	if err != nil {
		return nil, err
	}

	cumulativeGasUsed, err := strconv.ParseUint(strings.TrimPrefix(raw.CumulativeGasUsed, "0x"), 16, 64)
	if err != nil {
		return nil, err
	}

	transactionHash, err := HashFromHex(raw.TransactionHash)
	if err != nil {
		return nil, err
	}

	transactionIndex, err := strconv.ParseUint(strings.TrimPrefix(raw.TransactionIndex, "0x"), 16, 64)
	if err != nil {
		return nil, err
	}

	blockHash, err := HashFromHex(raw.BlockHash)
	if err != nil {
		return nil, err
	}

	blockNumber, ok := big.NewInt(0).SetString(strings.TrimPrefix(raw.BlockNumber, "0x"), 16)
	if !ok {
		return nil, errors.New("failed to extract block number from receipt")
	}

	gasUsed, err := strconv.ParseUint(strings.TrimPrefix(raw.GasUsed, "0x"), 16, 64)
	if err != nil {
		return nil, err
	}

	effectiveGasPrice, ok := big.NewInt(0).SetString(strings.TrimPrefix(raw.EffectiveGasPrice, "0x"), 16)
	if !ok {
		return nil, errors.New("failed to extract effective gas price from receipt")
	}

	var contractAddress Address
	if raw.ContractAddress != "" && raw.ContractAddress != "0x0000000000000000000000000000000000000000" {
		contractAddress = MustFromHex(raw.ContractAddress)
	}

	logs := make([]Log, 0, 20)
	for _, l := range raw.Logs {

		logIndex, err := strconv.ParseUint(strings.TrimPrefix(l.LogIndex, "0x"), 16, 64)
		if err != nil {
			return nil, err
		}

		logEntry := Log{
			Address:          MustFromHex(l.Address),
			Topics:           l.Topics,
			Data:             l.Data,
			TransactionIndex: transactionIndex,
			LogIndex:         logIndex,
		}

		logs = append(logs, logEntry)
	}

	receipt := &TransactionReceipt{
		Type:              int(txType),
		Status:            int(status),
		CumulativeGasUsed: cumulativeGasUsed,
		Logs:              logs,
		TransactionHash:   transactionHash,
		TransactionIndex:  transactionIndex,
		BlockHash:         blockHash,
		BlockNumber:       blockNumber,
		GasUsed:           gasUsed,
		EffectiveGasPrice: effectiveGasPrice,
		From:              MustFromHex(raw.From),
		To:                MustFromHex(raw.To),

		ContractAddress: &contractAddress,
	}

	return receipt, nil
}

func EncodeContractPayload(functionSignature string, args ...interface{}) ([]byte, error) {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(functionSignature))
	fullHash := hash.Sum(nil)
	selector := fullHash[:4] // selector is first 4 bytes of signature hash
	data := append([]byte{}, selector...)

	for _, arg := range args {
		encoded, err := encodeValue(arg)
		if err != nil {
			return nil, err
		}
		data = append(data, encoded[:]...) // append 32 bytes
	}

	return data, nil
}

// parseHexResponse parses eth_call response to structured data of type T.
//   - hexDataIn - input data as hex string
func parseHexResponse[T any](hexDataIn string) (*T, error) {
	hexDataIn = strings.TrimPrefix(hexDataIn, "0x")

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
		address := value.(Address)
		encodedValue = bytecast.LeftPadBytes00(address.Bytes(), 32)

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

// =================================== RLP Encoder (move to separate package) ==========================================

// RLPEncode — кодує значення у формат Recursive Length Prefix (RLP).
// Підтримує базові типи: string, uint64, byte, *big.Int, []string, []uint64, []byte, []*big.Int.
func RLPEncode(value interface{}) ([]byte, error) {

	switch v := value.(type) {
	case byte:
		return encodeBytes([]byte{v}), nil

	case []byte:
		return encodeBytes(v), nil

	case string:
		return encodeBytes([]byte(v)), nil

	case uint64:
		b := uintToBytesAndTrim(v)
		return encodeBytes(b), nil

	case *big.Int:
		if v == nil {
			// nil big.Int кодуємо як порожній рядок (RLP для 0)
			return encodeBytes([]byte{}), nil
		}
		return encodeBytes(v.Bytes()), nil

	default:
		reflectValue := reflect.ValueOf(value)
		if reflectValue.Kind() == reflect.Slice {
			var buf bytes.Buffer

			for i := 0; i < reflectValue.Len(); i++ {
				elem := reflectValue.Index(i).Interface()
				enc, err := RLPEncode(elem)
				if err != nil {
					return nil, err
				}
				buf.Write(enc)
			}

			if buf.Len() <= 55 {
				return append([]byte{byte(0xc0 + buf.Len())}, buf.Bytes()...), nil
			} else {
				bufLengthBytes := uintToBytesAndTrim(uint64(buf.Len()))
				prefix := 0xf7 + len(bufLengthBytes)

				return append(append([]byte{byte(prefix)}, bufLengthBytes...), buf.Bytes()...), nil
			}
		}
	}

	return nil, fmt.Errorf("unsupported RLP type: %T", value)
}

// encodeBytes encodes byte array according to RLP rules.
//
//	More info: https://ethereum.org/uk/developers/docs/data-structures-and-encoding/rlp/
func encodeBytes(b []byte) []byte {
	l := len(b)
	switch {

	case l == 1 && b[0] < 0x80:
		// For a single byte whose value is in the [0x00, 0x7f] (decimal [0, 127]) range,
		// that byte is its own RLP encoding.
		return b

	case l <= 55:
		// Otherwise, if a string is 0-55 bytes long,
		// the RLP encoding consists of a single byte with value 0x80 (dec. 128) plus the length of the string followed by the string.
		// The range of the first byte is thus [0x80, 0xb7] (dec. [128, 183]).
		return append([]byte{byte(0x80 + l)}, b...)

	default:
		// If a string is more than 55 bytes long,
		// the RLP encoding consists of a single byte with value 0xb7 (dec. 183) plus the length in bytes of the length of the string in binary form,
		// followed by the length of the string, followed by the string.
		// For example, a 1024 byte long string would be encoded as \xb9\x04\x00 (dec. 185, 4, 0) followed by the string. Here, 0xb9 (183 + 2 = 185) as the first byte, followed by the 2 bytes 0x0400 (dec. 1024) that denote the length of the actual string. The range of the first byte is thus [0xb8, 0xbf] (dec. [184, 191]).
		lengthInBytes := uintToBytesAndTrim(uint64(l))
		prefix := 0xb7 + len(lengthInBytes)
		return append(append([]byte{byte(prefix)}, lengthInBytes...), b...)
	}
}

// uintToBytesAndTrim — Converts uint64 to byte slice and cut off leading zeros.
func uintToBytesAndTrim(u uint64) []byte {
	if u == 0 {
		// Positive integers must be represented in big-endian binary form with no leading zeroes
		// (thus making the integer value zero equivalent to the empty byte array).
		return []byte{}
	}

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, u)

	b = bytes.TrimLeft(b, "\x00")

	return b
}

// =====================================================================================================================

// =================================== GAS (KEEP IN SEPARATE FILE IN BLOCKCHAIN BASICS PACKAGE) ========================

type GasParams struct {
	Type int // 0 for legacy, 2 for EIP1559

	// EIP1559 Gas Parameters
	GasTipCap *big.Int // a.k.a. maxPriorityFeePerGas, "tip" для майнерів
	GasFeeCap *big.Int // a.k.a. maxFeePerGas, верхня межа загальної ціни газу

	// Gas limit for contract execution, EIP1559 & Legacy!
	TransactionGasLimit uint64

	// Legacy Gas Parameters
	GasPrice *big.Int
}

// GetGasParams returns gas parameters, supports actual (EIP-1559) as well as LEGACY headers, see GasParams.Type
//
//	https://ethereum.org/uk/developers/docs/gas/#how-are-gas-fees-calculated
func GetGasParams(rpcURL string, from Address, to Address, data []byte, value *big.Int) (GasParams, error) {

	block, err := GetBlock(rpcURL, nil)
	if err != nil {
		return GasParams{}, err
	}

	transactionGasEstimate, err := EstimateGas(rpcURL, from, to, data, value)
	if err != nil {
		return GasParams{}, err
	}

	baseFee := block.BaseFeePerGas

	if baseFee.BitLen() != 0 { // EIP1559
		maxPriorityFeePerGas := big.NewInt(100_000_000) // TODO: make adjustable. 100_000_000 is OK for L2 network, but For L1 better to propose 2_000_000_000

		twentyFivePercentFromBaseFee := big.NewInt(0)
		twentyFivePercentFromBaseFee.Quo(baseFee, big.NewInt(4))

		extendedPricePerGas := big.NewInt(0) // a.k.a. maxFeePerGas (1.25*baseFee + gasTipCap)
		extendedPricePerGas.Add(baseFee, twentyFivePercentFromBaseFee).Add(extendedPricePerGas, maxPriorityFeePerGas)

		return GasParams{
			Type: 2,

			GasTipCap:           maxPriorityFeePerGas,
			GasFeeCap:           extendedPricePerGas,
			TransactionGasLimit: transactionGasEstimate,

			GasPrice: nil,
		}, nil
	}

	legacyGasPrice, err := getLegacyGasPrice(rpcURL)
	if err != nil {
		return GasParams{}, err
	}

	// Trying to overcome the error from BSC: "transaction underpriced: gas tip cap 50000000, minimum needed 100000000"
	if commonPrice := big.NewInt(100_000_000); legacyGasPrice.Cmp(commonPrice) == -1 {
		legacyGasPrice.Set(commonPrice)
	} else {
		twentyFivePercentFromLegacyGasPrice := big.NewInt(0)
		twentyFivePercentFromLegacyGasPrice.Quo(legacyGasPrice, big.NewInt(4))
		legacyGasPrice.Add(legacyGasPrice, twentyFivePercentFromLegacyGasPrice)
	}

	return GasParams{
		Type: 0,

		GasTipCap:           nil,
		GasFeeCap:           nil,
		TransactionGasLimit: transactionGasEstimate,

		GasPrice: legacyGasPrice,
	}, nil
}

// EstimateGas — estimates needed gas amount to execute transaction. Calls eth_estimateGas RPC method under the hood.
//
//	The transaction is not actually executed.
func EstimateGas(rpcURL string, from Address, to Address, data []byte, value *big.Int) (uint64, error) {
	// eth_estimateGas expect params as array with ONE element - json object with packed parameters into.
	// See https://www.quicknode.com/docs/ethereum/eth_estimateGas for example.
	params := []interface{}{
		map[string]string{
			"from": from.Hex(),
			"to":   to.Hex(),
			"data": "0x" + hex.EncodeToString(data),
			"value": func() string {
				if value == nil {
					return "0x0"
				}
				return "0x" + value.Text(16)
			}(),
		},
	}

	rawJson, err := ethereumMethodCall(rpcURL, "eth_estimateGas", params)
	if err != nil {
		return 0, fmt.Errorf("estimateGas RPC error: %s", err)
	}

	var hexValue string // результат — hex string (наприклад, "0x5208")
	if err = json.Unmarshal(rawJson, &hexValue); err != nil {
		return 0, err
	}

	gas, err := strconv.ParseUint(strings.TrimPrefix(hexValue, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}

	return gas, nil
}

func getLegacyGasPrice(rpcURL string) (*big.Int, error) {
	rawJson, err := ethereumMethodCall(rpcURL, "eth_gasPrice", []interface{}{})
	if err != nil {
		return nil, fmt.Errorf("failed to request LEGACY gas price: %s", err)
	}

	var hexValue string // результат — hex string (наприклад, "0x5208")
	if err = json.Unmarshal(rawJson, &hexValue); err != nil {
		return nil, fmt.Errorf("failed to request LEGACY gas price: %s", err)
	}

	if hexValue == "0x" {
		return big.NewInt(0), nil
	}

	hexValue = strings.TrimPrefix(hexValue, "0x")
	bigIntValue, ok := big.NewInt(0).SetString(hexValue, 16)

	if !ok {
		return nil, fmt.Errorf("failed to request LEGACY gas price, got invalid hex value")
	}

	return bigIntValue, nil
}

// =====================================================================================================================

// =================================== BLOCKCHAIN BASICS ===============================================================

// Block represents information/structure of the block
type Block struct {
	BaseFeePerGas    *big.Int `json:"baseFeePerGas,string"` // Базова комісія за газ (wei), added by EIP-1559 and is ignored in legacy headers
	Difficulty       *big.Int `json:"difficulty,string"`    // Складність майнінгу блоку (неактуально для L2), історично велике число
	ExtraData        []byte   `json:"extraData,string"`     // довільні дані (до 32 байт)
	GasLimit         uint64   `json:"gasLimit,string"`      // ліміт газу блоку (не виходить за межі 64 біт)
	GasUsed          uint64   `json:"gasUsed,string"`       // фактично використаний газ (не виходить за межі 64 біт)
	Hash             Hash     `json:"hash"`                 // хеш блоку
	L1BlockNumber    uint64   `json:"l1BlockNumber,string"` // номер L1-блоку (специфічно для Arbitrum)
	LogsBloom        []byte   `json:"logsBloom"`            // Bloom filter for logs (null if pending)
	Miner            *Address `json:"miner"`                // Address of the mining reward recipient.
	MixHash          Hash     `json:"mixHash"`              // хеш, що використовується в PoW
	Nonce            uint64   `json:"nonce,string"`         // A number of prior transactions from the sender.
	Number           *big.Int `json:"number,string"`        // номер блоку
	ParentHash       Hash     `json:"parentHash"`           // хеш попереднього блоку
	ReceiptsRoot     Hash     `json:"receiptsRoot"`         // корінь дерева отриманих квитанцій
	SendCount        uint64   `json:"sendCount"`            // кількість L2 транзакцій (Arbitrum)
	SendRoot         Hash     `json:"sendRoot"`             // хеш відправлених транзакцій (Arbitrum)
	Sha3Uncles       Hash     `json:"sha3Uncles"`           // SHA3 хеш усіх “дядьків”
	Size             uint64   `json:"size"`                 // розмір блоку у байтах
	StateRoot        Hash     `json:"stateRoot"`            // Root of the final state trie
	Timestamp        int64    `json:"timestamp,string"`     // час створення блоку (unix seconds)
	Transactions     []Hash   `json:"transactions"`         // список хешів транзакцій
	TransactionsRoot Hash     `json:"transactionsRoot"`     // корінь дерева транзакцій
	Uncles           []Hash   `json:"uncles"`               // Array of uncle block hashes
}

type Transaction1559 struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	To                   *Address // nil якщо створюємо контракт
	Value                *big.Int
	Data                 []byte
	AccessList           AccessList
	V, R, S              *big.Int // додаються після підпису
}

// AccessList is an EIP-2930 access list.
type AccessList []AccessTuple

// AccessTuple is the element type of an AccessList.
type AccessTuple struct {
	Address     Address
	StorageKeys []Hash
}

// TransactionLegacy is the transaction data of the original Ethereum transactions, still used, however, on Binance Smart Chain (BSC).
type TransactionLegacy struct {
	Nonce    uint64
	GasPrice *big.Int // wei per gas
	GasLimit uint64
	To       *Address // nil якщо створюємо контракт
	Value    *big.Int
	Data     []byte
	V, R, S  *big.Int // додаються після підпису
}

type rpcJsonResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"` // "result" field in rpcJsonResponse is always JSON. Compare to HEX-response in rpcContractResponse.
	Error   *RpcError       `json:"error,omitempty"`
}

type RpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e RpcError) Error() string {
	return fmt.Sprintf("RPC error #%d: %s", e.Code, e.Message)
}

func GetBlock(rpcURL string, blockNumber *big.Int) (Block, error) {
	blockNumberRendered := "latest"

	if blockNumber != nil {
		blockNumberRendered = "0x" + blockNumber.Text(16)
	}

	transaction_detail_flag := false // If true -> full transaction details retrieved, otherwise hashes only.

	rawJson, err := ethereumMethodCall(rpcURL, "eth_getBlockByNumber", []interface{}{blockNumberRendered, transaction_detail_flag})
	if err != nil {
		return Block{}, err
	}

	var block Block
	if err = json.Unmarshal(rawJson, &block); err != nil {
		return Block{}, err
	}

	return block, nil
}

func GetNonce(account Address, rpcURL string) (uint64, error) {
	rawJson, err := ethereumMethodCall(rpcURL, "eth_getTransactionCount", []interface{}{account.String(), "pending"})
	if err != nil {
		return 0, err
	}

	var hexValue string // результат — hex string (наприклад, "0x5208")
	if err = json.Unmarshal(rawJson, &hexValue); err != nil {
		return 0, err
	}

	nonce, err := strconv.ParseUint(strings.TrimPrefix(hexValue, "0x"), 16, 64)
	if err != nil {
		return 0, err
	}

	return nonce, nil
}

func (b *Block) UnmarshalJSON(bytes []byte) error {
	var item map[string]interface{}

	if err := json.Unmarshal(bytes, &item); err != nil {
		return err
	}

	block := Block{}
	blockReflectedValue := reflect.ValueOf(&block).Elem()

	for theirFieldName, theirFieldValue := range item {
		ourFieldName := strings.ToUpper(theirFieldName[:1]) + theirFieldName[1:]
		ourField := blockReflectedValue.FieldByName(ourFieldName)

		if !ourField.IsValid() {
			// We have not found field with given name locally. Maybe new field added in L2 block?
			// TODO: Add logging this incident as info/warning.
			continue
		}

		typedValue, err := parseDataToTypedValue(ourField.Type(), theirFieldValue)
		if err != nil {
			return err
		}

		ourField.Set(typedValue)
	}

	*b = block

	return nil
}

// ethereumMethodCall executes native eth method, like "eth_getBlockByNumber", "eth_estimateGas", "eth_call"
//
//	Intended to use only with ethereum methods, not direct with smart contract methods!
func ethereumMethodCall(rpcURL string, method string, params []interface{}) (json.RawMessage, error) {
	reqBody := map[string]interface{}{
		"id":      1, // TODO: Should we use this ID?
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		// Theoretically impossible error, so we panic here.
		// TODO: Maybe completely remove error checking here?
		panic("Error encoding payload to json (bad input?): " + err.Error())
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		// This can be runtime error, like bad connection, so NO PANIC, just return an error.
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("error reading response body: " + err.Error())
	}

	var rpcResponse rpcJsonResponse
	if err = json.Unmarshal(body, &rpcResponse); err != nil {
		return nil, errors.New("failed parsing json (inconsistent structure?): " + err.Error())
	}

	if rpcResponse.Error != nil {
		return nil, rpcResponse.Error
	}

	if rpcResponse.Result == nil {
		return nil, errors.New("RPC returned null")
	}

	return rpcResponse.Result, nil // we return RAW JSON value encoded as []byte
}

func parseDataToTypedValue(targetType reflect.Type, data any) (reflect.Value, error) {
	switch targetType {

	case reflect.TypeOf([]Hash{}):
		length := len(data.([]interface{}))
		sliceOfHashesReflect := reflect.MakeSlice(reflect.TypeOf([]Hash{}), 0, length)

		for _, hexHash := range data.([]interface{}) {
			hashValue, err := parseDataToTypedValue(reflect.TypeOf(Hash{}), hexHash.(string))
			if err != nil {
				return reflect.Value{}, err
			}

			sliceOfHashesReflect = reflect.Append(sliceOfHashesReflect, hashValue)
		}

		return sliceOfHashesReflect, nil

	case reflect.TypeOf((*big.Int)(nil)):
		if data == nil || data.(string) == "0x" {
			return reflect.ValueOf(big.NewInt(0)), nil
		}

		hexValue := strings.TrimPrefix(data.(string), "0x")
		bigIntValue := big.NewInt(0)
		bigIntValue.SetString(hexValue, 16)
		return reflect.ValueOf(bigIntValue), nil

	case reflect.TypeOf(int64(0)):
		hexValue := strings.TrimPrefix(data.(string), "0x")
		int64Value, err := strconv.ParseInt(hexValue, 16, 64)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(int64Value), nil

	case reflect.TypeOf(uint64(0)):
		hexValue := strings.TrimPrefix(data.(string), "0x")
		uint64Value, err := strconv.ParseUint(hexValue, 16, 64)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(uint64Value), nil

	case reflect.TypeOf([]byte{}):
		hexValue := strings.TrimPrefix(data.(string), "0x")
		b, err := hex.DecodeString(hexValue)
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(b), nil

	case reflect.TypeOf(Hash{}):
		hash, err := HashFromHex(data.(string))
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(hash), nil

	case reflect.TypeOf(Address{}):
		address, err := AddressFromHex(data.(string))
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(address), nil

	case reflect.TypeOf((*Address)(nil)):
		address, err := AddressFromHex(data.(string))
		if err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(&address), nil
	}

	panic(fmt.Sprintf("failed to parse block data - unknown type: %v", targetType.String()))
}

func buildRawTransaction1559(
	chainID *big.Int,
	nonce uint64,
	to *Address,
	gas GasParams,
	value *big.Int,
	data []byte,

) (*Transaction1559, error) {
	if chainID == nil {
		return nil, errors.New("chainID is required")
	}

	if nonce < 0 {
		return nil, errors.New("nonce is required and should be not negative")
	}

	tx := Transaction1559{
		ChainID:              chainID,
		Nonce:                nonce,
		MaxPriorityFeePerGas: gas.GasTipCap,
		MaxFeePerGas:         gas.GasFeeCap,
		GasLimit:             gas.TransactionGasLimit,
		To:                   to,
		Value:                value,
		Data:                 data,
		AccessList:           AccessList{},
		V:                    big.NewInt(0),
		R:                    big.NewInt(0),
		S:                    big.NewInt(0),
	}

	return &tx, nil
}

func rlpEncodeTransaction1559ForSigning(tx *Transaction1559) ([]byte, error) {
	// An EIP-1559 (Type 2) transaction's RLP-encoded prefix is the byte 0x02, indicating its type,
	// followed by the RLP-encoded list of transaction fields:
	// chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, and s (in that specific order),
	// all themselves RLP-encoded. This structure is different from legacy transactions, which lack the type byte and have a different field order.
	list := []interface{}{
		tx.ChainID,
		tx.Nonce,
		tx.MaxPriorityFeePerGas,
		tx.MaxFeePerGas,
		tx.GasLimit,
		func() []byte {
			if tx.To == nil {
				return []byte{}
			}
			return tx.To.Bytes()
		}(),
		tx.Value,
		tx.Data,
		[]interface{}{}, // AccessList пустий
	}

	encodedList, err := RLPEncode(list)
	if err != nil {
		return nil, err
	}

	// Транзакції EIP-1559 завжди мають префікс типу 0x02 перед RLP-кодом.
	return append([]byte{0x02}, encodedList...), nil
}

func rlpEncodeTransaction1559AfterSigning(tx *Transaction1559) ([]byte, error) {
	// An EIP-1559 (Type 2) transaction's RLP-encoded prefix is the byte 0x02, indicating its type,
	// followed by the RLP-encoded list of transaction fields:
	// chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, and s (in that specific order),
	// all themselves RLP-encoded. This structure is different from legacy transactions, which lack the type byte and have a different field order.
	list := []interface{}{
		tx.ChainID,
		tx.Nonce,
		tx.MaxPriorityFeePerGas,
		tx.MaxFeePerGas,
		tx.GasLimit,
		func() []byte {
			if tx.To == nil {
				return []byte{}
			}
			return tx.To.Bytes()
		}(),
		tx.Value,
		tx.Data,
		[]interface{}{}, // AccessList пустий
		tx.V,
		tx.R,
		tx.S,
	}

	encodedList, err := RLPEncode(list)
	if err != nil {
		return nil, err
	}

	// Транзакції EIP-1559 завжди мають префікс типу 0x02 перед RLP-кодом.
	return append([]byte{0x02}, encodedList...), nil
}

func hashTransaction(rlpEncoded []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(rlpEncoded)
	return h.Sum(nil)
}

func buildRawTransactionLegacy(nonce uint64, to *Address, gas GasParams, value *big.Int, data []byte) (*TransactionLegacy, error) {
	if nonce < 0 {
		return nil, errors.New("nonce is required and should be not negative")
	}

	tx := TransactionLegacy{
		Nonce:    nonce,
		GasPrice: gas.GasPrice,
		GasLimit: gas.TransactionGasLimit,
		To:       to,
		Value:    value,
		Data:     data,
	}

	return &tx, nil
}

func rlpEncodeTransactionLegacyForSigning(tx *TransactionLegacy, chainID *big.Int) ([]byte, error) {
	list := []interface{}{
		tx.Nonce,
		tx.GasPrice,
		tx.GasLimit,
		func() []byte {
			if tx.To == nil {
				return []byte{}
			}
			return tx.To.Bytes()
		}(),
		tx.Value,
		tx.Data,

		// EIP-155 extras
		chainID,
		uint64(0),
		uint64(0),
	}

	return RLPEncode(list)
}

func rlpEncodeTransactionLegacyAfterSigning(tx *TransactionLegacy) ([]byte, error) {
	list := []interface{}{
		tx.Nonce,
		tx.GasPrice,
		tx.GasLimit,
		func() []byte {
			if tx.To == nil {
				return []byte{}
			}
			return tx.To.Bytes()
		}(),
		tx.Value,
		tx.Data,
		tx.V,
		tx.R,
		tx.S,
	}

	return RLPEncode(list)
}

// =====================================================================================================================

// =================================== LOGS PARSER & ABI DECODER =======================================================

type TransactionReceipt struct {
	Type              int
	Status            int // 1 = success, 0 = revert
	CumulativeGasUsed uint64
	Logs              []Log
	TransactionHash   Hash
	TransactionIndex  uint64 // Position of transaction inside block. Numeration from 0.
	LogIndex          uint64 // Position of the log in the list of all block logs.
	BlockHash         Hash
	BlockNumber       *big.Int
	GasUsed           uint64
	EffectiveGasPrice *big.Int
	From              Address
	To                Address

	ContractAddress *Address // Optional parameter, not nil for deploy
}

type Log struct {
	Address Address // контракт-емітер
	// Topic structure:
	// 	topics[0] - eventID, identifier of event type (what happened) (keccak256(EventSignature))
	// 	topics[1..3] - indexed parameters (max 3)
	Topics           []string
	Data             string // hex ABI data
	TransactionIndex uint64
	LogIndex         uint64
}

type ABIType int

const (
	ABIAddress ABIType = iota
	ABIUint256
	ABIBool
	ABIBytes32
)

type ABIEventParam struct {
	Name    string
	Type    ABIType
	Indexed bool
}

type ABIEvent struct {
	Name   string
	Params []ABIEventParam
}

func (e ABIEvent) ID() Hash {
	sig := e.Name + "("
	for i, p := range e.Params {
		if i > 0 {
			sig += ","
		}
		sig += abiTypeToString(p.Type)
	}
	sig += ")"

	return GetEventID(sig)
}

func abiTypeToString(t ABIType) string {
	switch t {
	case ABIAddress:
		return "address"
	case ABIUint256:
		return "uint256"
	case ABIBool:
		return "bool"
	case ABIBytes32:
		return "bytes32"
	default:
		panic("unsupported ABI type")
	}
}

type DecodedEvent struct {
	Name   string
	Fields map[string]interface{}
}

// DecodeEvent decodes log event to structured data with typed fields
//
//	Usage example. User describes event he wants to decode:
//	approvalEvent := ABIEvent{
//		Name: "Approval",
//		Params: []ABIEventParam{
//			{Name: "owner", Type: ABIAddress, Indexed: true},
//			{Name: "spender", Type: ABIAddress, Indexed: true},
//			{Name: "value", Type: ABIUint256, Indexed: false},
//		},
//	}
//
//	Decode it:
//		ev, err := DecodeEvent(log, approvalEvent)
//
//	Assert types:
//		owner := ev.Fields["owner"].(Address)
//		spender := ev.Fields["spender"].(Address)
//		value := ev.Fields["value"].(*big.Int)
//		fmt.Println("Approval:", owner, spender, value)
func DecodeEvent(log Log, event ABIEvent) (*DecodedEvent, error) {
	if len(log.Topics) == 0 {
		return nil, fmt.Errorf("log has no topics")
	}

	if log.Topics[0] != event.ID().Hex() {
		return nil, fmt.Errorf("event signature mismatch")
	}

	result := &DecodedEvent{
		Name:   event.Name,
		Fields: make(map[string]interface{}),
	}

	topicIndex := 1
	dataOffset := 0

	for _, p := range event.Params {
		if p.Indexed {
			if topicIndex >= len(log.Topics) {
				return nil, fmt.Errorf("missing indexed topic")
			}

			topicHash, err := HashFromHex(log.Topics[topicIndex])
			if err != nil {
				return nil, err
			}

			value, err := decodeData(topicHash[:], p.Type)
			if err != nil {
				return nil, err
			}

			result.Fields[p.Name] = value
			topicIndex++
		} else {
			if dataOffset+32 > len(log.Data) {
				return nil, fmt.Errorf("data too short")
			}

			hexValue := strings.TrimPrefix(log.Data, "0x")
			bytesValue, err := hex.DecodeString(hexValue)
			if err != nil {
				return nil, err
			}

			chunk := bytesValue[dataOffset : dataOffset+32]

			value, err := decodeData(chunk, p.Type)
			if err != nil {
				return nil, err
			}

			result.Fields[p.Name] = value
			dataOffset += 32
		}
	}

	return result, nil
}

// TODO: Implement more types using bytecast
func decodeData(b []byte, t ABIType) (interface{}, error) {
	switch t {

	case ABIAddress:
		var addr Address
		copy(addr[:], b[12:32]) // last 20 bytes
		return addr, nil

	case ABIUint256:
		return new(big.Int).SetBytes(b), nil

	case ABIBool:
		return b[31] == 1, nil

	case ABIBytes32:
		var out Hash
		copy(out[:], b)
		return out, nil

	default:
		return nil, fmt.Errorf("unsupported ABI type")
	}
}

// GetEventID calculates hash id for given event. For example:
//
//	transferID := GetEventID("Transfer(address,address,uint256)")
func GetEventID(eventSignature string) Hash {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(eventSignature))

	sum := h.Sum(nil)
	if len(sum) != 32 {
		// Why panic? Because it's impossible to have length other than 32 here.
		panic(fmt.Errorf("invalid keccak256 length: %d", len(sum)))
	}

	var hash Hash
	copy(hash[:], sum)
	return hash
}

func (r *TransactionReceipt) LogsByEvent(eventID Hash) []Log {
	out := make([]Log, 0, 10)
	for _, l := range r.Logs {
		// Event signature (event ID) is always in Topics[0]!
		if len(l.Topics) > 0 && strings.EqualFold(l.Topics[0], eventID.Hex()) {
			out = append(out, l)
		}
	}
	return out
}

func (r *TransactionReceipt) LogsByAddress(addr Address) []Log {
	out := make([]Log, 0, 10)
	for _, l := range r.Logs {
		if l.Address == addr {
			out = append(out, l)
		}
	}
	return out
}

func (r *TransactionReceipt) LogsByEventAndAddress(addr Address, eventID Hash) []Log {
	out := make([]Log, 0, 10)
	for _, l := range r.Logs {
		if len(l.Topics) > 0 && strings.EqualFold(l.Topics[0], eventID.Hex()) && l.Address == addr {
			out = append(out, l)
		}
	}
	return out
}

// =====================================================================================================================

// =================================== SECP256K1 MINIMAL IMPLEMENTATION ================================================

// SECP256K1Curve implements minimal secp256k1 with basic ScalarBaseMult and ScalarMult
type SECP256K1Curve struct {
	*elliptic.CurveParams
}

func InitSECP256K1Curve() elliptic.Curve {

	// General elliptic curve:
	// y² = x³ + ax + b (mod p)
	//
	// secp256k1 elliptic curve:
	// y² = x³ + 7 (mod p)
	//
	// secp256k1 curve params:
	// 	B = 7 -- just common value
	// 	P = 2²⁵⁶ - 2³² - 977 -- prime field (big PRIME number)
	//	G = (Gx, Gy) -- starting point of generation
	//	d -- Private key, big random number
	//	Q = d × G -- Public key, × here is not multiplication, but multiple addition of a point
	//	N -- is the order of the generator, the smallest number N such that N × G = a point at infinity; private key d ∈ [1, N-1]
	// 	BitSize = 256 -- this curve ~256 bits of security
	//
	// Elliptic Curve Discrete Logarithm Problem:
	// 	EASY: Q = d × G
	//	ALMOST NOT POSSIBLE: d = log_G(Q)

	params := new(elliptic.CurveParams)

	params.Name = "secp256k1"
	params.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	params.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	params.B = big.NewInt(7)
	params.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	params.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	params.BitSize = 256

	return &SECP256K1Curve{params}
}

// IsOnCurve перевіряє, що точка (x,y) лежить на кривій y² = x³ + 7 mod P
func (c *SECP256K1Curve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 {
		return false
	}
	p := c.P
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, p)

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, c.B)
	x3.Mod(x3, p)

	return y2.Cmp(x3) == 0
}

// Add повертає P + Q на кривій
func (c *SECP256K1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p := c.P
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	var m, x3, y3 big.Int

	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		// Point doubling
		two := big.NewInt(2)
		three := big.NewInt(3)

		num := new(big.Int).Mul(three, new(big.Int).Mul(x1, x1))
		num.Mod(num, p)

		den := new(big.Int).Mul(two, y1)
		den.ModInverse(den, p)

		m.Mul(num, den)
		m.Mod(&m, p)
	} else {
		// Point addition
		num := new(big.Int).Sub(y2, y1)
		den := new(big.Int).Sub(x2, x1)
		den.ModInverse(den, p)

		m.Mul(num, den)
		m.Mod(&m, p)
	}

	x3.Mul(&m, &m)
	x3.Sub(&x3, x1)
	x3.Sub(&x3, x2)
	x3.Mod(&x3, p)

	y3.Sub(x1, &x3)
	y3.Mul(&y3, &m)
	y3.Sub(&y3, y1)
	y3.Mod(&y3, p)

	return &x3, &y3
}

// ScalarMult обчислює k*(x,y)
func (c *SECP256K1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	x, y := big.NewInt(0), big.NewInt(0)
	for _, b := range k {
		for i := 7; i >= 0; i-- {
			x, y = c.Add(x, y, x, y) // double
			if (b>>uint(i))&1 == 1 {
				x, y = c.Add(x, y, Bx, By)
			}
		}
	}
	return x, y
}

// ScalarBaseMult обчислює k*G
func (c *SECP256K1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.ScalarMult(c.Gx, c.Gy, k)
}

func LoadPrivateKey(hexKey string, secp256k1 elliptic.Curve) (*ecdsa.PrivateKey, error) {
	keyBytes, err := hex.DecodeString(strings.TrimPrefix(hexKey, "0x"))
	if err != nil {
		return nil, err
	}

	private := new(ecdsa.PrivateKey)
	private.PublicKey.Curve = secp256k1
	private.D = new(big.Int).SetBytes(keyBytes)
	private.PublicKey.X, private.PublicKey.Y = secp256k1.ScalarBaseMult(keyBytes)

	return private, nil
}

func GetAddressFromPrivateKey(privateKey *ecdsa.PrivateKey) Address {
	pubX := privateKey.PublicKey.X
	pubY := privateKey.PublicKey.Y

	return GetAddressFromPublicKey(pubX, pubY)
}

func GetAddressFromPublicKey(pubX, pubY *big.Int) Address {
	// General formula of address calculation: address = last20bytes( keccak256(pubkey[64]) )

	xBytes := pubX.Bytes()
	yBytes := pubY.Bytes()

	// гарантовано 32 байти кожен
	paddedX := append(make([]byte, 32-len(xBytes)), xBytes...)
	paddedY := append(make([]byte, 32-len(yBytes)), yBytes...)

	pubkey := append(paddedX, paddedY...)

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubkey)
	sum := hash.Sum(nil)

	var addr Address
	copy(addr[:], sum[12:]) // last 20 bytes

	return addr
}

func Sign1559Hash(hash []byte, privateKey *ecdsa.PrivateKey, secp256k1 elliptic.Curve) (v, r, s *big.Int, err error) {

	r, s, err = ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, nil, nil, err
	}

	// EIP-2: normalize S
	curveN := secp256k1.Params().N
	halfN := new(big.Int).Rsh(curveN, 1)
	if s.Cmp(halfN) == 1 {
		s.Sub(curveN, s)
	}

	// v = recovery id (0 or 1)
	// Стандартний ecdsa.Sign НЕ повертає recoveryID,
	// тому ми обчислюємо його вручну:
	recID := recoverID(privateKey.PublicKey.X, privateKey.PublicKey.Y, r, s, hash, secp256k1)

	return big.NewInt(int64(recID)), r, s, nil
}

func recoverID(pubX, pubY, r, s *big.Int, hash []byte, secp256k1 elliptic.Curve) int {
	// brute-force: пробуємо v=0 і v=1
	for v := 0; v <= 1; v++ {
		x, y := recoverPublicKey(r, s, hash, v, secp256k1)
		if x != nil && x.Cmp(pubX) == 0 && y.Cmp(pubY) == 0 {
			return v
		}
	}
	panic("failed to recover v")
}

func modSqrt(y2, p *big.Int) *big.Int {
	// p % 4 == 3 для secp256k1 → sqrt = y2^((p+1)/4)
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	return new(big.Int).Exp(y2, exp, p)
}

func recoverPublicKey(r, s *big.Int, hash []byte, v int, secp256k1 elliptic.Curve) (*big.Int, *big.Int) {
	params := secp256k1.Params()

	z := new(big.Int).SetBytes(hash)
	z.Mod(z, params.N)

	// 1. Відновлюємо R.x = r
	x := new(big.Int).Set(r)

	// y² = x³ + 7 mod p
	y2 := new(big.Int).Exp(x, big.NewInt(3), params.P)
	y2.Add(y2, params.B)
	y2.Mod(y2, params.P)

	y := modSqrt(y2, params.P)
	if y == nil {
		return nil, nil
	}

	// Вибір знаку y через v
	if y.Bit(0) != uint(v) {
		y.Sub(params.P, y)
	}

	if !secp256k1.IsOnCurve(x, y) {
		return nil, nil
	}

	// 2. r⁻¹ mod N
	rInv := new(big.Int).ModInverse(r, params.N)
	if rInv == nil {
		return nil, nil
	}

	// s·R
	sR_x, sR_y := secp256k1.ScalarMult(x, y, s.Bytes())

	// z·G
	zG_x, zG_y := secp256k1.ScalarBaseMult(z.Bytes())
	zG_y.Neg(zG_y).Mod(zG_y, params.P)

	// sR − zG
	Qx, Qy := secp256k1.Add(sR_x, sR_y, zG_x, zG_y)

	// r⁻¹ · (sR − zG)
	Qx, Qy = secp256k1.ScalarMult(Qx, Qy, rInv.Bytes())

	return Qx, Qy
}

// =====================================================================================================================
