// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	Alloc      GenesisAlloc        `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
	BaseFee    *big.Int    `json:"baseFeePerGas"`
}

// GenesisAlloc specifies the initial state that is part of the genesis block.
type GenesisAlloc map[common.Address]GenesisAccount

func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code       []byte                      `json:"code,omitempty"`
	Storage    map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance    *big.Int                    `json:"balance" gencodec:"required"`
	Nonce      uint64                      `json:"nonce,omitempty"`
	PrivateKey []byte                      `json:"secretKey,omitempty"` // for tests
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	BaseFee    *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database contains incompatible genesis (have %x, new %x)", e.Stored, e.New)
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                          genesis == nil       genesis != nil
//                       +------------------------------------------
//     db has no genesis |  main-net default  |  genesis
//     db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
//
// The returned chain configuration is never nil.
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, error) {
	return SetupGenesisBlockWithOverride(db, genesis, nil)
}

func SetupGenesisBlockWithOverride(db ethdb.Database, genesis *Genesis, overrideArrowGlacier *big.Int) (*params.ChainConfig, common.Hash, error) {
	if genesis != nil && genesis.Config == nil {
		return params.AllEthashProtocolChanges, common.Hash{}, errGenesisNoConfig
	}
	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if (stored == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = GamechainGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		if err != nil {
			return genesis.Config, common.Hash{}, err
		}
		return genesis.Config, block.Hash(), nil
	}
	// We have the genesis block in database(perhaps in ancient database)
	// but the corresponding state is missing.
	header := rawdb.ReadHeader(db, stored, 0)
	if _, err := state.New(header.Root, state.NewDatabaseWithConfig(db, nil), nil); err != nil {
		if genesis == nil {
			genesis = GamechainGenesisBlock()
		}
		// Ensure the stored genesis matches with the given one.
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
		block, err := genesis.Commit(db)
		if err != nil {
			return genesis.Config, hash, err
		}
		return genesis.Config, block.Hash(), nil
	}
	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		if hash != stored {
			return genesis.Config, hash, &GenesisMismatchError{stored, hash}
		}
	}
	// Get the existing chain configuration.
	newcfg := genesis.configOrDefault(stored)
	if overrideArrowGlacier != nil {
		newcfg.ArrowGlacierBlock = overrideArrowGlacier
	}
	if err := newcfg.CheckConfigForkOrder(); err != nil {
		return newcfg, common.Hash{}, err
	}
	storedcfg := rawdb.ReadChainConfig(db, stored)
	if storedcfg == nil {
		log.Warn("Found genesis block without chain config")
		rawdb.WriteChainConfig(db, stored, newcfg)
		return newcfg, stored, nil
	}
	// Special case: don't change the existing config of a non-mainnet chain if no new
	// config is supplied. These chains would get AllProtocolChanges (and a compat error)
	// if we just continued here.
	if genesis == nil && stored != params.MainnetGenesisHash {
		return storedcfg, stored, nil
	}
	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {
		return newcfg, stored, fmt.Errorf("missing block number for head header hash")
	}
	compatErr := storedcfg.CheckCompatible(newcfg, *height)
	if compatErr != nil && *height != 0 && compatErr.RewindTo != 0 {
		return newcfg, stored, compatErr
	}
	rawdb.WriteChainConfig(db, stored, newcfg)
	return newcfg, stored, nil
}

func (g *Genesis) configOrDefault(ghash common.Hash) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig
	case ghash == params.RopstenGenesisHash:
		return params.RopstenChainConfig
	case ghash == params.SepoliaGenesisHash:
		return params.SepoliaChainConfig
	case ghash == params.RinkebyGenesisHash:
		return params.RinkebyChainConfig
	case ghash == params.GoerliGenesisHash:
		return params.GoerliChainConfig
	default:
		return params.AllEthashProtocolChanges
	}
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db ethdb.Database) *types.Block {
	if db == nil {
		db = rawdb.NewMemoryDatabase()
	}
	statedb, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		panic(err)
	}
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance)
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root := statedb.IntermediateRoot(false)
	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Timestamp,
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		BaseFee:    g.BaseFee,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	if g.Config != nil && g.Config.IsLondon(common.Big0) {
		if g.BaseFee != nil {
			head.BaseFee = g.BaseFee
		} else {
			head.BaseFee = new(big.Int).SetUint64(params.InitialBaseFee)
		}
	}
	statedb.Commit(false)
	statedb.Database().TrieDB().Commit(root, true, nil)

	return types.NewBlock(head, nil, nil, nil, trie.NewStackTrie(nil))
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	block := g.ToBlock(db)
	if block.Number().Sign() != 0 {
		return nil, errors.New("can't commit genesis block with number > 0")
	}
	config := g.Config
	if config == nil {
		config = params.AllEthashProtocolChanges
	}
	if err := config.CheckConfigForkOrder(); err != nil {
		return nil, err
	}
	if config.Clique != nil && len(block.Extra()) == 0 {
		return nil, errors.New("can't start clique chain without signers")
	}
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), block.Difficulty())
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadFastBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteChainConfig(db, block.Hash(), config)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// GenesisBlockForTesting creates and writes a block in which addr has the given wei balance.
func GenesisBlockForTesting(db ethdb.Database, addr common.Address, balance *big.Int) *types.Block {
	g := Genesis{
		Alloc:   GenesisAlloc{addr: {Balance: balance}},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	return g.MustCommit(db)
}

// DefaultGenesisBlock returns the Ethereum main net genesis block.
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.MainnetChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
		GasLimit:   5000,
		Difficulty: big.NewInt(17179869184),
		Alloc:      decodePrealloc(mainnetAllocData),
	}
}

// DefaultRopstenGenesisBlock returns the Ropsten network genesis block.
func DefaultRopstenGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.RopstenChainConfig,
		Nonce:      66,
		ExtraData:  hexutil.MustDecode("0x3535353535353535353535353535353535353535353535353535353535353535"),
		GasLimit:   16777216,
		Difficulty: big.NewInt(1048576),
		Alloc:      decodePrealloc(ropstenAllocData),
	}
}

// DefaultRinkebyGenesisBlock returns the Rinkeby network genesis block.
func DefaultRinkebyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.RinkebyChainConfig,
		Timestamp:  1492009146,
		ExtraData:  hexutil.MustDecode("0x52657370656374206d7920617574686f7269746168207e452e436172746d616e42eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(rinkebyAllocData),
	}
}

// DefaultGoerliGenesisBlock returns the Görli network genesis block.
func DefaultGoerliGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.GoerliChainConfig,
		Timestamp:  1548854791,
		ExtraData:  hexutil.MustDecode("0x22466c6578692069732061207468696e6722202d204166726900000000000000e0a2bd4258d2768837baa26a28fe71dc079f84c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   10485760,
		Difficulty: big.NewInt(1),
		Alloc:      decodePrealloc(goerliAllocData),
	}
}

// DefaultSepoliaGenesisBlock returns the Sepolia network genesis block.
func DefaultSepoliaGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.SepoliaChainConfig,
		Nonce:      0,
		ExtraData:  []byte("Sepolia, Athens, Attica, Greece!"),
		GasLimit:   0x1c9c380,
		Difficulty: big.NewInt(0x20000),
		Timestamp:  1633267481,
		Alloc:      decodePrealloc(sepoliaAllocData),
	}
}

func GamechainGenesisBlock() *Genesis {
	faucet := common.HexToAddress("0x42CB208DD023232464835e5e817e81865D198250")

	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique = &params.CliqueConfig{
		Period: 3,
		Epoch:  config.Clique.Epoch,
	}
	alloc := map[common.Address]GenesisAccount{
		common.BytesToAddress([]byte{1}):                                {Balance: big.NewInt(1)}, // ECRecover
		common.BytesToAddress([]byte{2}):                                {Balance: big.NewInt(1)}, // SHA256
		common.BytesToAddress([]byte{3}):                                {Balance: big.NewInt(1)}, // RIPEMD
		common.BytesToAddress([]byte{4}):                                {Balance: big.NewInt(1)}, // Identity
		common.BytesToAddress([]byte{5}):                                {Balance: big.NewInt(1)}, // ModExp
		common.BytesToAddress([]byte{6}):                                {Balance: big.NewInt(1)}, // ECAdd
		common.BytesToAddress([]byte{7}):                                {Balance: big.NewInt(1)}, // ECScalarMul
		common.BytesToAddress([]byte{8}):                                {Balance: big.NewInt(1)}, // ECPairing
		common.BytesToAddress([]byte{9}):                                {Balance: big.NewInt(1)}, // BLAKE2b
		common.BytesToAddress(params.MasternodeContractAddress.Bytes()): masternodeContractAccount(),
		faucet: {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
	}
	for _, n := range params.MainnetMasternodes {
		addr := common.HexToAddress(n)
		if _, ok := alloc[addr]; !ok {
			alloc[addr] = GenesisAccount{
				Balance: new(big.Int).Mul(big.NewInt(1e+3), big.NewInt(1e+15)),
			}
		}
	}
	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, crypto.SignatureLength)...),
		GasLimit:   11500000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(1),
		Alloc:      alloc,
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block.
//func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique = &params.CliqueConfig{
		Period: period,
		Epoch:  config.Clique.Epoch,
	}

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, crypto.SignatureLength)...),
		GasLimit:   11500000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]GenesisAccount{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			common.BytesToAddress([]byte{9}): {Balance: big.NewInt(1)}, // BLAKE2b
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

func decodePrealloc(data string) GenesisAlloc {
	var p []struct{ Addr, Balance *big.Int }
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		ga[common.BigToAddress(account.Addr)] = GenesisAccount{Balance: account.Balance}
	}
	return ga
}

func masternodeContractAccount() GenesisAccount {
	var (
		data        = make(map[common.Hash]common.Hash)
		nextNodeKey common.Hash
		lastNode    common.Address
		count       = int64(len(params.MainnetMasternodes))
	)

	for i, n := range params.MainnetMasternodes {
		investor := common.HexToAddress(params.Investors[i])
		currentNode := common.HexToAddress(n)

		// Set node.nextNode of lastNode
		if nextNodeKey != (common.Hash{}) {
			var currentNodeVal common.Hash
			copy(currentNodeVal[12:32], currentNode.Bytes())
			data[nextNodeKey] = currentNodeVal
		}

		// Keys of node
		var nodeKeyRaw [64]byte
		nodeKeyRaw[63] = 7
		copy(nodeKeyRaw[12:32], currentNode.Bytes())
		nodeKey := new(big.Int).SetBytes(crypto.Keccak256(nodeKeyRaw[:]))
		preNodeKey := common.BytesToHash(nodeKey.Bytes())                              // preNode
		nextNodeKey = common.BytesToHash(nodeKey.Add(nodeKey, big.NewInt(1)).Bytes())  // nextNode
		investorKey := common.BytesToHash(nodeKey.Add(nodeKey, big.NewInt(3)).Bytes()) // investor & status

		// Set preNode
		var preNodeVal common.Hash
		copy(preNodeVal[12:32], lastNode.Bytes())
		data[preNodeKey] = preNodeVal

		// Set investor
		var investorVal common.Hash
		copy(investorVal[12:32], investor.Bytes())
		investorVal[11] = 1
		data[investorKey] = investorVal

		// Key of investor2nid
		var investor2nidKeyRaw [64]byte
		investor2nidKeyRaw[63] = 8
		copy(investor2nidKeyRaw[12:32], investor.Bytes())
		investor2nidKey := common.BytesToHash(crypto.Keccak256(investor2nidKeyRaw[:]))
		data[investor2nidKey] = common.BytesToHash(currentNode.Bytes())

		// Set lastNode
		lastNode = currentNode
	}
	var lastNodeVal common.Hash
	copy(lastNodeVal[12:32], lastNode.Bytes())
	data[common.HexToHash("00")] = lastNodeVal                                       // lastNode
	data[common.HexToHash("02")] = common.BytesToHash(big.NewInt(count).Bytes())     // countTotalNode
	data[common.HexToHash("05")] = common.BytesToHash(big.NewInt(1200).Bytes())      // releaseBlocks
	data[common.HexToHash("06")] = common.BytesToHash(params.MasternodeCost.Bytes()) // nodeCost

	//for k, v := range data {
	//	fmt.Printf("data[common.HexToHash(\"%s\")] = common.HexToHash(\"%s\")\n", k.String(), v.String())
	//}

	return GenesisAccount{
		Balance: big.NewInt(1),
		Nonce:   0,
		Storage: data,
		Code:    hexutil.MustDecode("0x6080604052600436106101385760003560e01c8063677321da116100ab5780638f35a75e1161006f5780638f35a75e146107c55780639382255714610802578063a737b1861461082d578063a8365f6114610858578063e331c4391461086f578063eb5821861461089a57610139565b8063677321da146106d6578063684c2611146106f257806369438d7b1461073257806370d1d0311461076f57806373b150981461079a57610139565b8063200fc3ff116100fd578063200fc3ff146105ef57806321887c3d1461061a57806331deb7e1146106575780634420e48614610682578063551619131461069e5780635a9b0b89146106a857610139565b8062b54ea61461052357806304ad33bb1461054e5780631209f7ed14610579578063189a5a17146105905780631f3c99c3146105d857610139565b5b34801561014557600080fd5b50600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160149054906101000a900460ff1660ff166001146101db576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101d2906124f7565b60405180910390fd5b600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060154600014610260576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161025790612563565b60405180910390fd5b43600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601819055506001600360008282546102ba91906125bc565b92505081905550600073ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146103bb573360076000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550005b34801561052f57600080fd5b506105386108d7565b6040516105459190612621565b60405180910390f35b34801561055a57600080fd5b506105636108dd565b604051610570919061267d565b60405180910390f35b34801561058557600080fd5b5061058e610903565b005b34801561059c57600080fd5b506105b760048036038101906105b291906126c9565b610c36565b6040516105cf9c9b9a99989796959493929190612712565b60405180910390f35b3480156105e457600080fd5b506105ed610d43565b005b3480156105fb57600080fd5b506106046111bf565b604051610611919061267d565b60405180910390f35b34801561062657600080fd5b50610641600480360381019061063c91906126c9565b6111e3565b60405161064e91906127e7565b60405180910390f35b34801561066357600080fd5b5061066c611242565b6040516106799190612621565b60405180910390f35b61069c60048036038101906106979190612840565b611248565b005b6106a6611255565b005b3480156106b457600080fd5b506106bd611257565b6040516106cd949392919061286d565b60405180910390f35b6106f060048036038101906106eb91906128b2565b611288565b005b3480156106fe57600080fd5b50610719600480360381019061071491906126c9565b611a00565b604051610729949392919061286d565b60405180910390f35b34801561073e57600080fd5b50610759600480360381019061075491906126c9565b611c2a565b6040516107669190612621565b60405180910390f35b34801561077b57600080fd5b50610784611df2565b6040516107919190612621565b60405180910390f35b3480156107a657600080fd5b506107af611df8565b6040516107bc9190612621565b60405180910390f35b3480156107d157600080fd5b506107ec60048036038101906107e791906126c9565b611dfe565b6040516107f9919061267d565b60405180910390f35b34801561080e57600080fd5b50610817611e6a565b6040516108249190612621565b60405180910390f35b34801561083957600080fd5b50610842611e76565b60405161084f9190612621565b60405180910390f35b34801561086457600080fd5b5061086d611e7c565b005b34801561087b57600080fd5b5061088461202a565b6040516108919190612621565b60405180910390f35b3480156108a657600080fd5b506108c160048036038101906108bc91906126c9565b612030565b6040516108ce919061267d565b60405180910390f35b60035481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600860003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156109d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109ce9061293e565b60405180910390fd5b6000600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070154118015610a7b57506002600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160149054906101000a900460ff1660ff16145b610aba576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610ab1906129aa565b60405180910390fd5b600760008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701544311610b3e576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b3590612a16565b60405180910390fd5b6000610b4982611c2a565b905080600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206009016000828254610b9d91906125bc565b9250508190555043600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f19350505050158015610c31573d6000803e3d6000fd5b505050565b60076020528060005260406000206000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060040160149054906101000a900460ff169080600501549080600601549080600701549080600801549080600901549080600a015490508c565b6000600860003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600760008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160149054906101000a900460ff1660ff16600114610e3c576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610e3390612a82565b60405180910390fd5b610e4581612063565b6000600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614610fc95780600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146110835781600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506110c4565b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b6001600460008282546110d791906125bc565b9250508190555043600760008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701819055506002600760008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160146101000a81548160ff021916908360ff1602179055507f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa16583336040516111b2929190612aa2565b60405180910390a1505050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60006001600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160149054906101000a900460ff1660ff16149050919050565b60065481565b6112528133611288565b50565b565b600080600080670de0b6b3a7640000476112719190612afa565b935060025492506003549150600454905090919293565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156112f8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016112ef90612b77565b60405180910390fd5b600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160149054906101000a900460ff1660ff1660001461138d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161138490612be3565b60405180910390fd5b600860008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff161461145b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161145290612c4f565b60405180910390fd5b600654341461149f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161149690612cbb565b60405180910390fd5b60405180610180016040528060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff168152602001600160ff1681526020014381526020016000815260200160008152602001670de0b6b3a764000060065461158e9190612cdb565b8152602001600081526020016000815250600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060408201518160020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060608201518160030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060808201518160040160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060a08201518160040160146101000a81548160ff021916908360ff16021790555060c0820151816005015560e0820151816006015561010082015181600701556101208201518160080155610140820151816009015561016082015181600a0155905050600073ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461189c5781600760008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555081600860008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060016002600082825461196d91906125bc565b925050819055508173ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a76400009081150290604051600060405180830381858888f193505050501580156119c2573d6000803e3d6000fd5b507fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e82826040516119f4929190612d6e565b60405180910390a15050565b6000806000806000600860008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600760008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600a015494506002600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160149054906101000a900460ff1660ff161415611c2257611b1381611c2a565b935083600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060090154600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060080154611ba69190612cdb565b611bb09190612cdb565b92506000600554600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060080154611c049190612afa565b905060038185611c149190612afa565b611c1e9190612d97565b9250505b509193509193565b60006002600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160149054906101000a900460ff1660ff1614611c8f5760009050611ded565b6000600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007015443611cdf9190612cdb565b90506000600554600760008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060080154611d339190612afa565b905060008183611d439190612d97565b90506000600760008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060090154600760008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060080154611dd79190612cdb565b905080821115611de5578091505b819450505050505b919050565b60055481565b60025481565b6000600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b670de0b6b3a764000081565b61032081565b6000600860003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415611f50576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611f479061293e565b60405180910390fd5b6000600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600a015490506000600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600a01819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f19350505050158015612025573d6000803e3d6000fd5b505050565b60045481565b60086020528060005260406000206000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601541115612497576001600360008282546120c19190612cdb565b925050819055506000600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601819055506000600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16146123165780600760008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600760008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146124525781600760008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600760008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550612494565b81600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b50505b50565b600082825260208201905092915050565b7f496e76616c69642073656e646572210000000000000000000000000000000000600082015250565b60006124e1600f8361249a565b91506124ec826124ab565b602082019050919050565b60006020820190508181036000830152612510816124d4565b9050919050565b7f416c7265616479206f6e6c696e65210000000000000000000000000000000000600082015250565b600061254d600f8361249a565b915061255882612517565b602082019050919050565b6000602082019050818103600083015261257c81612540565b9050919050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006125c782612583565b91506125d283612583565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156126075761260661258d565b5b828201905092915050565b61261b81612583565b82525050565b60006020820190506126366000830184612612565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006126678261263c565b9050919050565b6126778161265c565b82525050565b6000602082019050612692600083018461266e565b92915050565b600080fd5b6126a68161265c565b81146126b157600080fd5b50565b6000813590506126c38161269d565b92915050565b6000602082840312156126df576126de612698565b5b60006126ed848285016126b4565b91505092915050565b600060ff82169050919050565b61270c816126f6565b82525050565b600061018082019050612728600083018f61266e565b612735602083018e61266e565b612742604083018d61266e565b61274f606083018c61266e565b61275c608083018b61266e565b61276960a083018a612703565b61277660c0830189612612565b61278360e0830188612612565b612791610100830187612612565b61279f610120830186612612565b6127ad610140830185612612565b6127bb610160830184612612565b9d9c50505050505050505050505050565b60008115159050919050565b6127e1816127cc565b82525050565b60006020820190506127fc60008301846127d8565b92915050565b600061280d8261263c565b9050919050565b61281d81612802565b811461282857600080fd5b50565b60008135905061283a81612814565b92915050565b60006020828403121561285657612855612698565b5b60006128648482850161282b565b91505092915050565b60006080820190506128826000830187612612565b61288f6020830186612612565b61289c6040830185612612565b6128a96060830184612612565b95945050505050565b600080604083850312156128c9576128c8612698565b5b60006128d78582860161282b565b92505060206128e8858286016126b4565b9150509250929050565b7f446f6e27742068617665206e6f64650000000000000000000000000000000000600082015250565b6000612928600f8361249a565b9150612933826128f2565b602082019050919050565b600060208201905081810360008301526129578161291b565b9050919050565b7f4e6f74207965742072656c656173656400000000000000000000000000000000600082015250565b600061299460108361249a565b915061299f8261295e565b602082019050919050565b600060208201905081810360008301526129c381612987565b9050919050565b7f496e76616c696420626c6f636b4c617374576974686472617700000000000000600082015250565b6000612a0060198361249a565b9150612a0b826129ca565b602082019050919050565b60006020820190508181036000830152612a2f816129f3565b9050919050565b7f486173206265656e2072656c6561736564210000000000000000000000000000600082015250565b6000612a6c60128361249a565b9150612a7782612a36565b602082019050919050565b60006020820190508181036000830152612a9b81612a5f565b9050919050565b6000604082019050612ab7600083018561266e565b612ac4602083018461266e565b9392505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b6000612b0582612583565b9150612b1083612583565b925082612b2057612b1f612acb565b5b828204905092915050565b7f496e76616c6964206e6964210000000000000000000000000000000000000000600082015250565b6000612b61600c8361249a565b9150612b6c82612b2b565b602082019050919050565b60006020820190508181036000830152612b9081612b54565b9050919050565b7f546865206e696420686173206265656e20726567697374657265642100000000600082015250565b6000612bcd601c8361249a565b9150612bd882612b97565b602082019050919050565b60006020820190508181036000830152612bfc81612bc0565b9050919050565b7f546865206f776e6572206173206265656e207265676973746572656421000000600082015250565b6000612c39601d8361249a565b9150612c4482612c03565b602082019050919050565b60006020820190508181036000830152612c6881612c2c565b9050919050565b7f496e76616c6964206e6f6465436f737421000000000000000000000000000000600082015250565b6000612ca560118361249a565b9150612cb082612c6f565b602082019050919050565b60006020820190508181036000830152612cd481612c98565b9050919050565b6000612ce682612583565b9150612cf183612583565b925082821015612d0457612d0361258d565b5b828203905092915050565b6000819050919050565b6000612d34612d2f612d2a8461263c565b612d0f565b61263c565b9050919050565b6000612d4682612d19565b9050919050565b6000612d5882612d3b565b9050919050565b612d6881612d4d565b82525050565b6000604082019050612d836000830185612d5f565b612d90602083018461266e565b9392505050565b6000612da282612583565b9150612dad83612583565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615612de657612de561258d565b5b82820290509291505056fea26469706673582212205504107f432230b2ab3c2e61baef39b3023da9f1771afe2d59f31104793a099c64736f6c634300080a0033"),
	}
}
