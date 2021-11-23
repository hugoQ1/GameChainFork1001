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
	"github.com/ethereum/go-ethereum/p2p/enode"
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
	faucet := common.HexToAddress("0x046BC7B020dA804A2CF59c7097667cF8bB138389")

	// Override the default period to the user requested one
	config := *params.AllCliqueProtocolChanges
	config.Clique = &params.CliqueConfig{
		Period: 3,
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
			common.BytesToAddress(params.MasterndeContractAddress.Bytes()): masternodeContractAccount(params.MainnetMasternodes),
		},
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

func masternodeContractAccount(masternodes []string) GenesisAccount {
	var (
		investor = common.HexToAddress("0x046BC7B020dA804A2CF59c7097667cF8bB138389")
		data    = make(map[common.Hash]common.Hash)
		nextNodeKey common.Hash
		lastNode  common.Address
		count = int64(len(masternodes))
	)

	for _, n := range masternodes {
		pubkey := enode.MustParseV4(n).Pubkey()
		currentNode := crypto.PubkeyToAddress(*pubkey)

		// Set node.nextNode of lastNode
		if nextNodeKey != (common.Hash{}) {
			var currentNodeVal common.Hash
			copy(currentNodeVal[12:32], currentNode.Bytes())
			data[nextNodeKey] = currentNodeVal
		}

		// Keys of node
		var nodeKeyRaw [64]byte
		copy(nodeKeyRaw[12:32], currentNode.Bytes())
		nodeKeyRaw[63] = 4
		nodeKey := new(big.Int).SetBytes(crypto.Keccak256(nodeKeyRaw[:]))
		preNodeKey := common.BytesToHash(nodeKey.Bytes())                                // preNode
		nextNodeKey = common.BytesToHash(nodeKey.Add(nodeKey, big.NewInt(1)).Bytes()) // nextNode
		investorKey := common.BytesToHash(nodeKey.Add(nodeKey, big.NewInt(3)).Bytes()) // investor

		// Set preNode
		var preNodeVal common.Hash
		copy(preNodeVal[12:32], lastNode.Bytes())
		data[preNodeKey] = preNodeVal

		// Set investor
		var investorVal common.Hash
		copy(investorVal[12:32], investor.Bytes())
		data[investorKey] = investorVal

		// Set lastNode
		lastNode = currentNode
	}
	var lastNodeVal common.Hash
	copy(lastNodeVal[12:32], lastNode.Bytes())
	data[common.HexToHash("00")] = lastNodeVal
	data[common.HexToHash("01")] = common.BytesToHash(big.NewInt(count).Bytes())

	for k, v := range data {
		fmt.Printf("data[common.HexToHash(\"%s\")] = common.HexToHash(\"%s\")\n", k.String(), v.String())
	}

	return GenesisAccount{
		Balance: big.NewInt(1),
		Nonce:   0,
		Storage: data,
		Code:    hexutil.MustDecode("0x608060405260043610610104576000357c0100000000000000000000000000000000000000000000000000000000900480634420e486116100a7578063960d59f811610076578063960d59f8146114e7578063a737b1861461154b578063f90638a314611576578063ffdd5cf11461161457610104565b80634420e486146113e457806373b15098146114285780638f35a75e1461145357806393822557146114bc57610104565b8063200fc3ff116100e3578063200fc3ff1461125e57806321887c3d146112b557806331deb7e11461131e578063367d5e621461134957610104565b8062b54ea61461106357806304ad33bb1461108e578063189a5a17146110e5575b34801561011057600080fd5b50600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff1614151561076557600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070154600014156104b4576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701819055506001600360008282540192505081905550600073ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16141515610349573360046000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610643565b6000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601541115610642576000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601544303905061032081111561059f576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070181905550610640565b80600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007016000828254019250508190555080600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600801600082825401925050819055505b505b5b43600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601819055506106f5600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16611695565b610760600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16611695565b611061565b6000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905011156110605760006001600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805490500390506000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208281548110151561084857fe5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff161415151561091357600080fd5b61091c81611789565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141515610aa25780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515610b5e5781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610b9f565b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600080600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206005015411905061012060405190810160405280600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff1681526020016000815260200160008152602001600081526020016000815250600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060408201518160020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060608201518160030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060808201518160040160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060a0820151816005015560c0820151816006015560e0820151816007015561010082015181600801559050506000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002086815481101515610ebc57fe5b9060005260206000200160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555084600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081610f4f919061271d565b5060016002600082825403925050819055507f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa1658433604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a1801561105a573373ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a764000069021e19e0c9bab2400000039081150290604051600060405180830381858888f19350505050158015611058573d6000803e3d6000fd5b505b50505050505b5b005b34801561106f57600080fd5b50611078611bbb565b6040518082815260200191505060405180910390f35b34801561109a57600080fd5b506110a3611bc1565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3480156110f157600080fd5b506111346004803603602081101561110857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611be7565b604051808a73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001858152602001848152602001838152602001828152602001995050505050505050505060405180910390f35b34801561126a57600080fd5b50611273611cd5565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b3480156112c157600080fd5b50611304600480360360208110156112d857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611cfa565b604051808215151515815260200191505060405180910390f35b34801561132a57600080fd5b50611333611d95565b6040518082815260200191505060405180910390f35b34801561135557600080fd5b506113a26004803603604081101561136c57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050611da3565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b611426600480360360208110156113fa57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611df0565b005b34801561143457600080fd5b5061143d611dfd565b6040518082815260200191505060405180910390f35b34801561145f57600080fd5b506114a26004803603602081101561147657600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611e03565b604051808215151515815260200191505060405180910390f35b3480156114c857600080fd5b506114d1611e9e565b6040518082815260200191505060405180910390f35b611549600480360360408110156114fd57600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050611eaa565b005b34801561155757600080fd5b50611560612511565b6040518082815260200191505060405180910390f35b34801561158257600080fd5b506115cf6004803603604081101561159957600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919080359060200190929190505050612517565b6040518083815260200182600560200280838360005b838110156116005780820151818401526020810190506115e5565b505050509050019250505060405180910390f35b34801561162057600080fd5b506116636004803603602081101561163757600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff16906020019092919050505061267e565b604051808681526020018581526020018481526020018381526020018281526020019550505050505060405180910390f35b600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff1614151561178657610320600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060154430311156117855761178481611789565b5b5b50565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701541115611bb85760016003600082825403925050819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141515611a355780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16141515611b735781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550611bb5565b81600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b50505b50565b60035481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60046020528060005260406000206000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060050154908060060154908060070154908060080154905089565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008073ffffffffffffffffffffffffffffffffffffffff16600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614159050919050565b69021e19e0c9bab240000081565b600560205281600052604060002081815481101515611dbe57fe5b906000526020600020016000915091509054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b611dfa8133611eaa565b50565b60025481565b60008073ffffffffffffffffffffffffffffffffffffffff16600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614159050919050565b670de0b6b3a764000081565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614158015611f755750600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16145b8015611f8a575069021e19e0c9bab240000034145b1515611f9557600080fd5b610120604051908101604052806000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff16815260200143815260200160008152602001600081526020016000815250600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060408201518160020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060608201518160030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060808201518160040160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060a0820151816005015560c0820151816006015560e082015181600701556101008201518160080155905050600073ffffffffffffffffffffffffffffffffffffffff166000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161415156123335781600460008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600560008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208290806001815401808255809150509060018203906000526020600020016000909192909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505060016002600082825401925050819055508173ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a76400009081150290604051600060405180830381858888f19350505050158015612475573d6000803e3d6000fd5b507fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e8282604051808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a15050565b61032081565b6000612521612749565b6060600560008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054806020026020016040519081016040528092919081815260200182805480156125e257602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311612598575b505050505090508051925060008090505b600581108015612604575083858201105b15612675578185820181518110151561261957fe5b90602001906020020151838260058110151561263157fe5b602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff168152505080806001019150506125f3565b50509250929050565b6000806000806000670de0b6b3a76400003073ffffffffffffffffffffffffffffffffffffffff16318115156126b057fe5b049450600a603043028115156126c257fe5b04935060025492506003549150600560008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050905091939590929450565b81548183558181111561274457818360005260206000209182019101612743919061276c565b5b505050565b60a060405190810160405280600590602082028038833980820191505090505090565b61278e91905b8082111561278a576000816000905550600101612772565b5090565b9056fea165627a7a72305820b1b33d92154acd1d252b2b848e96a9fcf43693ca8347259e01e1e9b9a0ddda080029"),
	}
}
