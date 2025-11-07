package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/anxp/bytecast"
	"golang.org/x/crypto/sha3"
)

const (
	rpcURL      = "https://arb1.arbitrum.io/rpc"
	poolAddress = "0xf3eb87c1f6020982173c908e7eb31aa66c1f0296"
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

	token := MustFromHex("0x82af49447d8a07e3bd95bd0d56f35241523fbab1")
	spender := MustFromHex("0xf3eb87c1f6020982173c908e7eb31aa66c1f0296")
	owner := MustFromHex("0x1234567890abcdef1234567890abcdef12345678")

	// формуємо payload для approve(address,uint256)
	data, _ := encodeContractPayload("approve(address,uint256)", spender, big.NewInt(1000000000000000000))

	// оцінюємо gasLimit
	gasLimit, err := EstimateGas(rpcURL, owner, token, data, big.NewInt(0))
	if err != nil {
		panic(err)
	}

	fmt.Println("GasLimit (estimated):", gasLimit)

	block, err := GetBlock(rpcURL, nil)

	_ = block

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

// contractMethodCall executes method "functionSignature" of contract "contractAddress" with input parameters "args" and returns result of type T.
//
//	[READONLY] This is NOT-state-changing call
//
//	Usage examples:
//		tickInfo, err := contractMethodCall[TickResponse](rpcURL, poolAddress, "ticks(int24)", int32(-193252))
//		slot0Response, err := contractMethodCall[Slot0Response](rpcURL, poolAddress, "slot0()")
//		token0Response, err := contractMethodCall[Address](rpcURL, poolAddress, "token0()")
func contractMethodCall[T any](rpcURL, contractAddress, functionSignature string, args ...interface{}) (*T, error) {
	data, err := encodeContractPayload(functionSignature, args...)
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
	rawJson, err := callEthereumMethod(rpcURL, "eth_call", []interface{}{callObj, "latest"})
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

func encodeContractPayload(functionSignature string, args ...interface{}) ([]byte, error) {
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

type Gas1559Params struct {
	GasTipCap           *big.Int // a.k.a. maxPriorityFeePerGas, "tip" для майнерів
	GasFeeCap           *big.Int // a.k.a. maxFeePerGas, верхня межа загальної ціни газу
	TransactionGasLimit uint64   // ліміт для виконання
}

func GetGasParams(rpcURL string, from Address, to Address, data []byte, value *big.Int) (Gas1559Params, error) {

	block, err := GetBlock(rpcURL, nil)
	if err != nil {
		return Gas1559Params{}, err
	}

	// https://ethereum.org/uk/developers/docs/gas/#how-are-gas-fees-calculated

	maxPriorityFeePerGas := big.NewInt(100_000_000) // TODO: make adjustable. 100_000_000 is OK for L2 network, but For L1 better to propose 2_000_000_000

	twentyFivePercentFromBaseFee := big.NewInt(0)
	twentyFivePercentFromBaseFee.Quo(block.BaseFeePerGas, big.NewInt(4))

	extendedPricePerGas := big.NewInt(0) // a.k.a. maxFeePerGas (1.25*baseFee + gasTipCap)
	extendedPricePerGas.Add(block.BaseFeePerGas, twentyFivePercentFromBaseFee).Add(extendedPricePerGas, maxPriorityFeePerGas)

	transactionGasEstimate, err := EstimateGas(rpcURL, from, to, data, value)
	if err != nil {
		return Gas1559Params{}, err
	}

	return Gas1559Params{
		GasTipCap:           big.NewInt(100_000_000),
		GasFeeCap:           extendedPricePerGas,
		TransactionGasLimit: transactionGasEstimate,
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

	rawJson, err := callEthereumMethod(rpcURL, "eth_estimateGas", params)
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
	Miner            Address  `json:"miner"`                // Address of the mining reward recipient.
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

type rpcJsonResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"` // "result" field in rpcJsonResponse is always JSON. Compare to HEX-response in rpcContractResponse.
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func GetBlock(rpcURL string, blockNumber *big.Int) (Block, error) {
	blockNumberRendered := "latest"

	if blockNumber != nil {
		blockNumberRendered = blockNumber.String()
	}

	transaction_detail_flag := false // If true -> full transaction details retrieved, otherwise hashes only.

	rawJson, err := callEthereumMethod(rpcURL, "eth_getBlockByNumber", []interface{}{blockNumberRendered, transaction_detail_flag})
	if err != nil {
		return Block{}, err
	}

	var block Block
	if err = json.Unmarshal(rawJson, &block); err != nil {
		return Block{}, err
	}

	return block, nil
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

// callEthereumMethod executes native eth method, like "eth_getBlockByNumber", "eth_estimateGas"
//
//	Intended to use only with ethereum methods, not direct with smart contract methods!
func callEthereumMethod(rpcURL string, method string, params []interface{}) (json.RawMessage, error) {
	reqBody := map[string]interface{}{
		"id":      1, // TODO: Should we use this ID?
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		panic("Logic error on encoding payload to json in callEthereumMethod: " + err.Error())
	}

	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		// This can be runtime error, like bad connection, so NO PANIC, just return an error.
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// TODO: Check which types of errors can appear here
		panic("Error on reading response body (TODO: CHECK IF THIS IS LOGIC OR RUNTIME ERROR): " + err.Error())
	}

	var rpcResponse rpcJsonResponse
	if err = json.Unmarshal(body, &rpcResponse); err != nil {
		// TODO: Check which types of errors can appear here
		panic("Error on decoding json (TODO: CHECK IF THIS IS LOGIC OR RUNTIME ERROR): " + err.Error())
	}
	if rpcResponse.Error != nil {
		return nil, errors.New(fmt.Sprintf("%s (code %d)", rpcResponse.Error.Message, rpcResponse.Error.Code))
	}

	rawJson := rpcResponse.Result

	return rawJson, nil
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
	}

	panic(fmt.Sprintf("failed to parse block data - unknown type: %v", targetType.String()))
}

// =====================================================================================================================
