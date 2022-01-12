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
		Code:    hexutil.MustDecode("0x6080604052600436106101655760003560e01c80635fa0deff116100d15780638f35a75e1161008a578063c55ae72f11610064578063c55ae72f1461067d578063d0a2ef021461069d578063e331c439146106bd578063eb582186146106d357610165565b80638f35a75e14610610578063938225571461064c578063a8365f611461066857610165565b80635fa0deff1461055b578063677321da14610591578063684c2611146105a457806369438d7b146105c457806370d1d031146105e457806373b15098146105fa57610165565b806321887c3d1161012357806321887c3d1461048757806331deb7e1146104dd5780634420e486146104f3578063543e1a561461050657806355161913146103505780635a9b0b891461052657610165565b8062b54ea6146102da57806304ad33bb146103035780631209f7ed1461033b578063189a5a17146103525780631f3c99c314610452578063200fc3ff14610467575b34801561017157600080fd5b5033600090815260076020526040902060040154600160a01b900460ff166001146101d55760405162461bcd60e51b815260206004820152600f60248201526e496e76616c69642073656e6465722160881b60448201526064015b60405180910390fd5b33600090815260076020526040902060060154156102275760405162461bcd60e51b815260206004820152600f60248201526e416c7265616479206f6e6c696e652160881b60448201526064016101cc565b3360009081526007602052604081204360069091015560038054600192906102509084906113e8565b90915550506001546001600160a01b031615610294576001546001600160a01b0316600090815260076020526040902060030180546001600160a01b031916331790555b600180543360008181526007602052604090206002810180546001600160a01b039094166001600160a01b03199485161790556003018054831690558254909116179055005b3480156102e657600080fd5b506102f060035481565b6040519081526020015b60405180910390f35b34801561030f57600080fd5b50600154610323906001600160a01b031681565b6040516001600160a01b0390911681526020016102fa565b34801561034757600080fd5b50610350610709565b005b34801561035e57600080fd5b506103e061036d366004611415565b600760208190526000918252604090912080546001820154600283015460038401546004850154600586015460068701549787015460088801546009890154600a909901546001600160a01b039889169a97891699968916989586169795851696600160a01b90950460ff16959394908c565b604080516001600160a01b039d8e1681529b8d1660208d0152998c16998b0199909952968a1660608a015298909416608088015260ff90921660a087015260c086015260e0850152610100840152610120830193909352610140820192909252610160810191909152610180016102fa565b34801561045e57600080fd5b506103506108eb565b34801561047357600080fd5b50600054610323906001600160a01b031681565b34801561049357600080fd5b506104cd6104a2366004611415565b6001600160a01b0316600090815260076020526040902060040154600160a01b900460ff1660011490565b60405190151581526020016102fa565b3480156104e957600080fd5b506102f060065481565b610350610501366004611415565b610ab6565b34801561051257600080fd5b50600a54610323906001600160a01b031681565b34801561053257600080fd5b5061053b610ac3565b6040805194855260208501939093529183015260608201526080016102fa565b34801561056757600080fd5b50610323610576366004611415565b6009602052600090815260409020546001600160a01b031681565b61035061059f366004611439565b610af1565b3480156105b057600080fd5b5061053b6105bf366004611415565b610eca565b3480156105d057600080fd5b506102f06105df366004611415565b610fae565b3480156105f057600080fd5b506102f060055481565b34801561060657600080fd5b506102f060025481565b34801561061c57600080fd5b5061032361062b366004611415565b6001600160a01b039081166000908152600760205260409020600401541690565b34801561065857600080fd5b506102f0670de0b6b3a764000081565b34801561067457600080fd5b5061035061108d565b34801561068957600080fd5b50610350610698366004611415565b611134565b3480156106a957600080fd5b50600b54610323906001600160a01b031681565b3480156106c957600080fd5b506102f060045481565b3480156106df57600080fd5b506103236106ee366004611415565b6008602052600090815260409020546001600160a01b031681565b336000908152600860205260409020546001600160a01b0316806107615760405162461bcd60e51b815260206004820152600f60248201526e446f6e27742068617665206e6f646560881b60448201526064016101cc565b6001600160a01b03811660009081526007602081905260409091200154158015906107b157506001600160a01b038116600090815260076020526040902060040154600160a01b900460ff166002145b6107f05760405162461bcd60e51b815260206004820152601060248201526f139bdd081e595d081c995b19585cd95960821b60448201526064016101cc565b6001600160a01b03811660009081526007602081905260409091200154431161085b5760405162461bcd60e51b815260206004820152601960248201527f496e76616c696420626c6f636b4c61737457697468647261770000000000000060448201526064016101cc565b600061086682610fae565b6001600160a01b0383166000908152600760205260408120600901805492935083929091906108969084906113e8565b90915550506001600160a01b03821660009081526007602081905260408083204392019190915551339183156108fc02918491818181858888f193505050501580156108e6573d6000803e3d6000fd5b505050565b336000908152600860209081526040808320546001600160a01b031680845260079092529091206004015460ff600160a01b909104166001146109655760405162461bcd60e51b8152602060048201526012602482015271486173206265656e2072656c65617365642160701b60448201526064016101cc565b61096e816112a5565b6001600160a01b0380821660009081526007602052604090208054600190910154908216911681156109cc576001600160a01b03828116600090815260076020526040902060010180546001600160a01b0319169183169190911790555b6001600160a01b03811615610a0e576001600160a01b03818116600090815260076020526040902080546001600160a01b031916918416919091179055610a2a565b600080546001600160a01b0319166001600160a01b0384161790555b600160046000828254610a3d91906113e8565b90915550506001600160a01b03831660008181526007602081815260409283902043928101929092556004909101805460ff60a01b1916600160a11b179055815192835233908301527f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa165910160405180910390a1505050565b610ac08133610af1565b50565b6000808080610ada670de0b6b3a764000047611472565b935060025492506003549150600454905090919293565b6001600160a01b038216610b365760405162461bcd60e51b815260206004820152600c60248201526b496e76616c6964206e69642160a01b60448201526064016101cc565b6001600160a01b038216600090815260076020526040902060040154600160a01b900460ff1615610ba95760405162461bcd60e51b815260206004820152601c60248201527f546865206e696420686173206265656e2072656769737465726564210000000060448201526064016101cc565b6001600160a01b038082166000908152600860205260409020541615610c115760405162461bcd60e51b815260206004820152601d60248201527f546865206f776e6572206173206265656e20726567697374657265642100000060448201526064016101cc565b6006543414610c565760405162461bcd60e51b8152602060048201526011602482015270496e76616c6964206e6f6465436f73742160781b60448201526064016101cc565b6040805161018081018252600080546001600160a01b03908116835260208301829052928201819052606082018190529183166080820152600160a08201524360c082015260e08101829052610100810191909152600654610120820190610cc790670de0b6b3a764000090611494565b81526000602080830182905260409283018290526001600160a01b0380871683526007808352848420865181549084166001600160a01b0319918216178255938701516001820180549185169186169190911790559486015160028601805491841691851691909117905560608601516003860180549184169190941617909255608085015160048501805460a088015160ff16600160a01b026001600160a81b03199091169284169290921791909117905560c0850151600585015560e08501516006850155610100850151918401919091556101208401516008840155610140840151600984015561016090930151600a90920191909155541615610dfc57600080546001600160a01b0390811682526007602052604090912060010180546001600160a01b0319169184169190911790555b600080546001600160a01b038085166001600160a01b031992831681178455908416835260086020526040832080549092161790556002805460019290610e449084906113e8565b90915550506040516001600160a01b03831690600090670de0b6b3a76400009082818181858883f19350505050158015610e82573d6000803e3d6000fd5b50604080516001600160a01b038085168252831660208201527fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e910160405180910390a15050565b6001600160a01b038181166000908152600860209081526040808320549093168083526007909152918120600a81015460049091015490928291829190600160a01b900460ff1660021415610fa657610f2281610fae565b6001600160a01b038216600090815260076020526040902060098101546008909101549195508591610f549190611494565b610f5e9190611494565b6005546001600160a01b03831660009081526007602052604081206008015492955091610f8b9190611472565b9050610f978185611472565b610fa29060036114ab565b9250505b509193509193565b6001600160a01b038116600090815260076020526040812060040154600160a01b900460ff16600214610fe357506000919050565b6001600160a01b0382166000908152600760208190526040822001546110099043611494565b6005546001600160a01b038516600090815260076020526040812060080154929350916110369190611472565b9050600061104482846114ab565b6001600160a01b0386166000908152600760205260408120600981015460089091015492935090916110769190611494565b905080821115611084578091505b50949350505050565b336000908152600860205260409020546001600160a01b0316806110e55760405162461bcd60e51b815260206004820152600f60248201526e446f6e27742068617665206e6f646560881b60448201526064016101cc565b6001600160a01b038116600090815260076020526040808220600a0180549083905590519091339183156108fc0291849190818181858888f193505050501580156108e6573d6000803e3d6000fd5b336000818152600960205260409020546001600160a01b0316156111905760405162461bcd60e51b815260206004820152601360248201527243616e6e6f742072657065617420666f726b2160681b60448201526064016101cc565b600a546001600160a01b03161580156111b25750600b546001600160a01b0316155b6111fe5760405162461bcd60e51b815260206004820152601860248201527f506c65617365207761697420666f722061207768696c6521000000000000000060448201526064016101cc565b803b8061125b5760405162461bcd60e51b815260206004820152602560248201527f4f6e6c7920696e7472612d636f6e74726163742063616c6c7320626520616c6c6044820152646f7765642160d81b60648201526084016101cc565b50600a80546001600160a01b039384166001600160a01b03199182168117909255600b80549390941692811683179093556000918252600960205260409091208054909216179055565b6001600160a01b03811660009081526007602052604090206006015415610ac0576001600360008282546112d99190611494565b90915550506001600160a01b0380821660009081526007602052604081206006810191909155600281015460039091015490821691168115611359576001600160a01b0380831660009081526007602052604080822060030180548486166001600160a01b03199182161790915592861682529020600201805490911690555b6001600160a01b038116156113b0576001600160a01b0380821660009081526007602052604080822060020180548487166001600160a01b0319918216179091559286168252902060030180549091169055505050565b600180546001600160a01b0384166001600160a01b0319909116179055505050565b634e487b7160e01b600052601160045260246000fd5b600082198211156113fb576113fb6113d2565b500190565b6001600160a01b0381168114610ac057600080fd5b60006020828403121561142757600080fd5b813561143281611400565b9392505050565b6000806040838503121561144c57600080fd5b823561145781611400565b9150602083013561146781611400565b809150509250929050565b60008261148f57634e487b7160e01b600052601260045260246000fd5b500490565b6000828210156114a6576114a66113d2565b500390565b60008160001904831182151516156114c5576114c56113d2565b50029056fea2646970667358221220c9d5410d6a2febb48d2435d29f52de3b28ef62b5f625b0eacaa20d0b09b1dec864736f6c634300080a0033"),
	}
}
