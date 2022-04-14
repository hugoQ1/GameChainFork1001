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
	//faucet := common.HexToAddress("0x42CB208DD023232464835e5e817e81865D198250")
	faucet := common.HexToAddress("0xf96dD50192e15B102fd83365B66b48a20F64203d")

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
		Code:    hexutil.MustDecode("0x6080604052600436106101345760003560e01c8063677321da116100ab5780638f35a75e1161006f5780638f35a75e146105bf57806393822557146105fb578063a8365f6114610617578063c55ae72f1461062c578063e331c4391461064c578063eb5821861461066257610134565b8063677321da14610518578063684c26111461052b57806369438d7b1461057357806370d1d0311461059357806373b15098146105a957610134565b8063200fc3ff116100fd578063200fc3ff1461044457806321887c3d1461046457806331deb7e1146104ba5780634420e486146104d0578063551619131461031f5780635a9b0b89146104e357610134565b8062b54ea6146102a957806304ad33bb146102d25780631209f7ed1461030a578063189a5a17146103215780631f3c99c31461042f575b34801561014057600080fd5b5033600090815260076020526040902060040154600160a01b900460ff166001146101a45760405162461bcd60e51b815260206004820152600f60248201526e496e76616c69642073656e6465722160881b60448201526064015b60405180910390fd5b33600090815260076020526040902060060154156101f65760405162461bcd60e51b815260206004820152600f60248201526e416c7265616479206f6e6c696e652160881b604482015260640161019b565b33600090815260076020526040812043600690910155600380546001929061021f9084906113e3565b90915550506001546001600160a01b031615610263576001546001600160a01b0316600090815260076020526040902060030180546001600160a01b031916331790555b600180543360008181526007602052604090206002810180546001600160a01b039094166001600160a01b03199485161790556003018054831690558254909116179055005b3480156102b557600080fd5b506102bf60035481565b6040519081526020015b60405180910390f35b3480156102de57600080fd5b506001546102f2906001600160a01b031681565b6040516001600160a01b0390911681526020016102c9565b34801561031657600080fd5b5061031f610698565b005b34801561032d57600080fd5b506103b461033c366004611410565b600760208190526000918252604090912080546001820154600283015460038401546004850154600586015460068701549787015460088801546009890154600a8a0154600b909a01546001600160a01b03998a169b988a169a978a16999687169896861697600160a01b90960460ff16969495908d565b604080516001600160a01b039e8f1681529c8e1660208e01529a8d169a8c019a909a52978b1660608b015299909516608089015260ff90931660a088015260c087019190915260e08601526101008501526101208401526101408301939093526101608201929092526101808101919091526101a0016102c9565b34801561043b57600080fd5b5061031f61087a565b34801561045057600080fd5b506000546102f2906001600160a01b031681565b34801561047057600080fd5b506104aa61047f366004611410565b6001600160a01b0316600090815260076020526040902060040154600160a01b900460ff1660011490565b60405190151581526020016102c9565b3480156104c657600080fd5b506102bf60065481565b61031f6104de366004611410565b610a46565b3480156104ef57600080fd5b506104f8610a53565b6040805194855260208501939093529183015260608201526080016102c9565b61031f610526366004611434565b610a81565b34801561053757600080fd5b5061054b610546366004611410565b610e6c565b604080519586526020860194909452928401919091526060830152608082015260a0016102c9565b34801561057f57600080fd5b506102bf61058e366004611410565b610f5a565b34801561059f57600080fd5b506102bf60055481565b3480156105b557600080fd5b506102bf60025481565b3480156105cb57600080fd5b506102f26105da366004611410565b6001600160a01b039081166000908152600760205260409020600401541690565b34801561060757600080fd5b506102bf670de0b6b3a764000081565b34801561062357600080fd5b5061031f611039565b34801561063857600080fd5b5061031f610647366004611410565b6110e0565b34801561065857600080fd5b506102bf60045481565b34801561066e57600080fd5b506102f261067d366004611410565b6008602052600090815260409020546001600160a01b031681565b336000908152600860205260409020546001600160a01b0316806106f05760405162461bcd60e51b815260206004820152600f60248201526e446f6e27742068617665206e6f646560881b604482015260640161019b565b6001600160a01b038116600090815260076020819052604090912001541580159061074057506001600160a01b038116600090815260076020526040902060040154600160a01b900460ff166002145b61077f5760405162461bcd60e51b815260206004820152601060248201526f139bdd081e595d081c995b19585cd95960821b604482015260640161019b565b6001600160a01b0381166000908152600760208190526040909120015443116107ea5760405162461bcd60e51b815260206004820152601960248201527f496e76616c696420626c6f636b4c617374576974686472617700000000000000604482015260640161019b565b60006107f582610f5a565b6001600160a01b0383166000908152600760205260408120600901805492935083929091906108259084906113e3565b90915550506001600160a01b03821660009081526007602081905260408083204392019190915551339183156108fc02918491818181858888f19350505050158015610875573d6000803e3d6000fd5b505050565b336000908152600860209081526040808320546001600160a01b031680845260079092529091206004015460ff600160a01b909104166001146108f45760405162461bcd60e51b8152602060048201526012602482015271486173206265656e2072656c65617365642160701b604482015260640161019b565b6108fd81611264565b6001600160a01b03808216600090815260076020526040902080546001909101549082169116811561095b576001600160a01b03828116600090815260076020526040902060010180546001600160a01b0319169183169190911790555b6001600160a01b0381161561099d576001600160a01b03818116600090815260076020526040902080546001600160a01b0319169184169190911790556109b9565b600080546001600160a01b0319166001600160a01b0384161790555b6001600460008282546109cc91906113e3565b90915550506001600160a01b03831660008181526007602081815260409283902043928101929092556004909101805460ff60a01b1916600160a11b179055815192835233908301527f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa16591015b60405180910390a1505050565b610a508133610a81565b50565b6000808080610a6a670de0b6b3a76400004761146d565b935060025492506003549150600454905090919293565b6001600160a01b038216610ac65760405162461bcd60e51b815260206004820152600c60248201526b496e76616c6964206e69642160a01b604482015260640161019b565b6001600160a01b038216600090815260076020526040902060040154600160a01b900460ff1615610b395760405162461bcd60e51b815260206004820152601c60248201527f546865206e696420686173206265656e20726567697374657265642100000000604482015260640161019b565b6001600160a01b038082166000908152600860205260409020541615610ba15760405162461bcd60e51b815260206004820152601d60248201527f546865206f776e6572206173206265656e207265676973746572656421000000604482015260640161019b565b6006543414610be65760405162461bcd60e51b8152602060048201526011602482015270496e76616c6964206e6f6465436f73742160781b604482015260640161019b565b604080516101a081018252600080546001600160a01b03908116835260208301829052928201819052606082018190529183166080820152600160a08201524360c082015260e08101829052610100810191909152600654610120820190610c5790670de0b6b3a76400009061148f565b815260006020808301829052604080840183905260609384018390526001600160a01b0380881684526007808452828520875181549084166001600160a01b03199182161782559488015160018201805491851691871691909117905592870151600284018054918416918616919091179055948601516003830180549183169190941617909255608085015160048201805460a088015160ff16600160a01b026001600160a81b03199091169285169290921791909117905560c0850151600582015560e085015160068201556101008501519381019390935561012084015160088401556101408401516009840155610160840151600a84015561018090930151600b90920191909155541615610d9e57600080546001600160a01b0390811682526007602052604090912060010180546001600160a01b0319169184169190911790555b600080546001600160a01b038085166001600160a01b031992831681178455908416835260086020526040832080549092161790556002805460019290610de69084906113e3565b90915550506040516001600160a01b03831690600090670de0b6b3a76400009082818181858883f19350505050158015610e24573d6000803e3d6000fd5b50604080516001600160a01b038085168252831660208201527fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e910160405180910390a15050565b6001600160a01b038181166000908152600860209081526040808320549093168083526007909152918120600a810154600b82015460049092015490939192918291829190600160a01b900460ff1660021415610f5057610ecc81610f5a565b6001600160a01b038216600090815260076020526040902060098101546008909101549195508591610efe919061148f565b610f08919061148f565b6005546001600160a01b03831660009081526007602052604081206008015492955091610f35919061146d565b9050610f41818561146d565b610f4c9060036114a6565b9250505b5091939590929450565b6001600160a01b038116600090815260076020526040812060040154600160a01b900460ff16600214610f8f57506000919050565b6001600160a01b038216600090815260076020819052604082200154610fb5904361148f565b6005546001600160a01b03851660009081526007602052604081206008015492935091610fe2919061146d565b90506000610ff082846114a6565b6001600160a01b038616600090815260076020526040812060098101546008909101549293509091611022919061148f565b905080821115611030578091505b50949350505050565b336000908152600860205260409020546001600160a01b0316806110915760405162461bcd60e51b815260206004820152600f60248201526e446f6e27742068617665206e6f646560881b604482015260640161019b565b6001600160a01b038116600090815260076020526040808220600a0180549083905590519091339183156108fc0291849190818181858888f19350505050158015610875573d6000803e3d6000fd5b6110e8611391565b6110f06113af565b6001600160a01b03831682523360208084019190915281604084600084600019f161111a57600080fd5b805160011415611169578051156111645760405162461bcd60e51b815260206004820152600e60248201526d496e76616c696420696e7075742160901b604482015260640161019b565b611226565b8051600214156111c2578051156111645760405162461bcd60e51b815260206004820152601e60248201527f5468652063616c6c6572206d757374206265206120636f6e7472616374210000604482015260640161019b565b805160031415611226578051156112265760405162461bcd60e51b815260206004820152602260248201527f54686520636f6e747261637420686173206265656e20696e697469616c697a65604482015261642160f01b606482015260840161019b565b604080516001600160a01b03851681523360208201527fcef34eae8f50e9e7369f1fe0973242562fc88687ca07b1e856397986cac6d3ad9101610a39565b6001600160a01b03811660009081526007602052604090206006015415610a5057600160036000828254611298919061148f565b90915550506001600160a01b0380821660009081526007602052604081206006810191909155600281015460039091015490821691168115611318576001600160a01b0380831660009081526007602052604080822060030180548486166001600160a01b03199182161790915592861682529020600201805490911690555b6001600160a01b0381161561136f576001600160a01b0380821660009081526007602052604080822060020180548487166001600160a01b0319918216179091559286168252902060030180549091169055505050565b600180546001600160a01b0384166001600160a01b0319909116179055505050565b60405180604001604052806002906020820280368337509192915050565b60405180602001604052806001906020820280368337509192915050565b634e487b7160e01b600052601160045260246000fd5b600082198211156113f6576113f66113cd565b500190565b6001600160a01b0381168114610a5057600080fd5b60006020828403121561142257600080fd5b813561142d816113fb565b9392505050565b6000806040838503121561144757600080fd5b8235611452816113fb565b91506020830135611462816113fb565b809150509250929050565b60008261148a57634e487b7160e01b600052601260045260246000fd5b500490565b6000828210156114a1576114a16113cd565b500390565b60008160001904831182151516156114c0576114c06113cd565b50029056fea2646970667358221220ff8ff5610634b514b1961c3b2901f09c53fd812914563746b446a0ad26546d8d64736f6c634300080b0033"),
	}
}

//0x6080604052600436106100eb5760003560e01c80634420e4861161008a578063960d59f811610059578063960d59f81461107e578063a737b1861461109a578063f90638a3146110c5578063ffdd5cf11461110357610e5f565b80634420e48614610fcf57806373b1509814610feb5780638f35a75e14611016578063938225571461105357610e5f565b8063200fc3ff116100c6578063200fc3ff14610eff57806321887c3d14610f2a57806331deb7e114610f67578063367d5e6214610f9257610e5f565b8062b54ea614610e6457806304ad33bb14610e8f578063189a5a1714610eba57610e5f565b36610e5f57600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff161461076457600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007015460001415610498576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007018190555060016003600082825461022c91906121e3565b92505081905550600073ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461032d573360046000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610642565b6000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601541115610641576000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060154436105339190612239565b905061032081111561058c576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007018190555061063f565b80600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070160008282546105de91906121e3565b9250508190555080600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600801600082825461063791906121e3565b925050819055505b505b5b43600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601819055506106f4600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16611144565b61075f600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16611144565b610e5d565b6000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805490501115610e5c5760006001600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805490506108009190612239565b90506000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002082815481106108555761085461226d565b5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16141561091e57600080fd5b6109278161123f565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614610aab5780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610b655781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610ba6565b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600080600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060050154119050600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556001820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556002820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556003820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556004820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905560058201600090556006820160009055600782016000905560088201600090555050600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480610d6357610d6261229c565b5b6001900381819060005260206000200160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690559055600160026000828254610dab9190612239565b925050819055507f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa1658433604051610de392919061230c565b60405180910390a18015610e56573373ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a764000069021e19e0c9bab2400000610e299190612239565b9081150290604051600060405180830381858888f19350505050158015610e54573d6000803e3d6000fd5b505b50505050505b5b005b600080fd5b348015610e7057600080fd5b50610e79611676565b604051610e869190612344565b60405180910390f35b348015610e9b57600080fd5b50610ea461167c565b604051610eb1919061235f565b60405180910390f35b348015610ec657600080fd5b50610ee16004803603810190610edc91906123ab565b6116a2565b604051610ef6999897969594939291906123d8565b60405180910390f35b348015610f0b57600080fd5b50610f14611790565b604051610f21919061235f565b60405180910390f35b348015610f3657600080fd5b50610f516004803603810190610f4c91906123ab565b6117b4565b604051610f5e9190612480565b60405180910390f35b348015610f7357600080fd5b50610f7c61184f565b604051610f899190612344565b60405180910390f35b348015610f9e57600080fd5b50610fb96004803603810190610fb491906124c7565b61185d565b604051610fc6919061235f565b60405180910390f35b610fe96004803603810190610fe49190612545565b6118ab565b005b348015610ff757600080fd5b506110006118b8565b60405161100d9190612344565b60405180910390f35b34801561102257600080fd5b5061103d600480360381019061103891906123ab565b6118be565b60405161104a9190612480565b60405180910390f35b34801561105f57600080fd5b50611068611959565b6040516110759190612344565b60405180910390f35b61109860048036038101906110939190612572565b611965565b005b3480156110a657600080fd5b506110af611f6d565b6040516110bc9190612344565b60405180910390f35b3480156110d157600080fd5b506110ec60048036038101906110e791906124c7565b611f73565b6040516110fa92919061265d565b60405180910390f35b34801561110f57600080fd5b5061112a600480360381019061112591906123ab565b6120f7565b60405161113b959493929190612686565b60405180910390f35b600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff161461123c57610320600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601544361122b9190612239565b111561123b5761123a8161123f565b5b5b50565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007015411156116735760016003600082825461129d9190612239565b925050819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16146114f25780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161461162e5781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550611670565b81600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b50505b50565b60035481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60046020528060005260406000206000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060050154908060060154908060070154908060080154905089565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008073ffffffffffffffffffffffffffffffffffffffff16600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614159050919050565b69021e19e0c9bab240000081565b6005602052816000526040600020818154811061187957600080fd5b906000526020600020016000915091509054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6118b58133611965565b50565b60025481565b60008073ffffffffffffffffffffffffffffffffffffffff16600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614159050919050565b670de0b6b3a764000081565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614158015611a305750600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16145b8015611a45575069021e19e0c9bab240000034145b611a4e57600080fd5b60405180610120016040528060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff16815260200143815260200160008152602001600081526020016000815250600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060408201518160020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060608201518160030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060808201518160040160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060a0820151816005015560c0820151816006015560e082015181600701556101008201518160080155905050600073ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614611de75781600460008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600560008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020829080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600160026000828254611eda91906121e3565b925050819055508173ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a76400009081150290604051600060405180830381858888f19350505050158015611f2f573d6000803e3d6000fd5b507fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e8282604051611f61929190612738565b60405180910390a15050565b61032081565b6000611f7d612188565b6000600560008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080548060200260200160405190810160405280929190818152602001828054801561203e57602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311611ff4575b505050505090508051925060005b600581108015612066575083858261206491906121e3565b105b156120ee5781858261207891906121e3565b815181106120895761208861226d565b5b60200260200101518382600581106120a4576120a361226d565b5b602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff168152505080806120e690612761565b91505061204c565b50509250929050565b6000806000806000670de0b6b3a76400004761211391906127d9565b9450600a603043612124919061280a565b61212e91906127d9565b935060025492506003549150600560008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050905091939590929450565b6040518060a00160405280600590602082028036833780820191505090505090565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006121ee826121aa565b91506121f9836121aa565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561222e5761222d6121b4565b5b828201905092915050565b6000612244826121aa565b915061224f836121aa565b925082821015612262576122616121b4565b5b828203905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603160045260246000fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006122f6826122cb565b9050919050565b612306816122eb565b82525050565b600060408201905061232160008301856122fd565b61232e60208301846122fd565b9392505050565b61233e816121aa565b82525050565b60006020820190506123596000830184612335565b92915050565b600060208201905061237460008301846122fd565b92915050565b600080fd5b612388816122eb565b811461239357600080fd5b50565b6000813590506123a58161237f565b92915050565b6000602082840312156123c1576123c061237a565b5b60006123cf84828501612396565b91505092915050565b6000610120820190506123ee600083018c6122fd565b6123fb602083018b6122fd565b612408604083018a6122fd565b61241560608301896122fd565b61242260808301886122fd565b61242f60a0830187612335565b61243c60c0830186612335565b61244960e0830185612335565b612457610100830184612335565b9a9950505050505050505050565b60008115159050919050565b61247a81612465565b82525050565b60006020820190506124956000830184612471565b92915050565b6124a4816121aa565b81146124af57600080fd5b50565b6000813590506124c18161249b565b92915050565b600080604083850312156124de576124dd61237a565b5b60006124ec85828601612396565b92505060206124fd858286016124b2565b9150509250929050565b6000612512826122cb565b9050919050565b61252281612507565b811461252d57600080fd5b50565b60008135905061253f81612519565b92915050565b60006020828403121561255b5761255a61237a565b5b600061256984828501612530565b91505092915050565b600080604083850312156125895761258861237a565b5b600061259785828601612530565b92505060206125a885828601612396565b9150509250929050565b600060059050919050565b600081905092915050565b6000819050919050565b6125db816122eb565b82525050565b60006125ed83836125d2565b60208301905092915050565b6000602082019050919050565b61260f816125b2565b61261981846125bd565b9250612624826125c8565b8060005b8381101561265557815161263c87826125e1565b9650612647836125f9565b925050600181019050612628565b505050505050565b600060c0820190506126726000830185612335565b61267f6020830184612606565b9392505050565b600060a08201905061269b6000830188612335565b6126a86020830187612335565b6126b56040830186612335565b6126c26060830185612335565b6126cf6080830184612335565b9695505050505050565b6000819050919050565b60006126fe6126f96126f4846122cb565b6126d9565b6122cb565b9050919050565b6000612710826126e3565b9050919050565b600061272282612705565b9050919050565b61273281612717565b82525050565b600060408201905061274d6000830185612729565b61275a60208301846122fd565b9392505050565b600061276c826121aa565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82141561279f5761279e6121b4565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006127e4826121aa565b91506127ef836121aa565b9250826127ff576127fe6127aa565b5b828204905092915050565b6000612815826121aa565b9150612820836121aa565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615612859576128586121b4565b5b82820290509291505056fea2646970667358221220ea551bded40cb98533e0653412ffef96b8fc1afaaeb61969546456ed2cb4fad764736f6c634300080a0033
//0x60806040526004361061012d5760003560e01c80636e50d9bf116100ab578063a737b1861161006f578063a737b1861461139f578063a7676366146113ca578063ebc07741146113f5578063f207564e14611433578063f90638a31461144f578063ffdd5cf11461148d576110cb565b80636e50d9bf1461128e57806373b15098146112cf5780638f35a75e146112fa57806393822557146113375780639c40a21d14611362576110cb565b806321887c3d116100f257806321887c3d146111c35780632e64cec11461120057806331deb7e11461120a578063367d5e621461123557806349c107fb14611272576110cb565b8062b54ea6146110d057806304ad33bb146110fb578063189a5a17146111265780631a30b52c1461116b578063200fc3ff14611198576110cb565b366110cb57600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16146107a657600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070154600014156104da576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007018190555060016003600082825461026e9190612f57565b92505081905550600073ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461036f573360046000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610684565b6000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601541115610683576000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060154436105759190612fad565b90506103208111156105ce576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070181905550610681565b80600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070160008282546106209190612f57565b9250508190555080600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060080160008282546106799190612f57565b925050819055505b505b5b43600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060181905550610736600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166114cd565b6107a1600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166114cd565b6110c9565b6000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905011156110c85760006001600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805490506108429190612fad565b90506000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020828154811061089757610896612fe1565b5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16141561096057600080fd5b610969816115c8565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614610aed5780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610ba75781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610be8565b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600080600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060050154119050600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556001820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556002820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556003820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556004820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905560058201600090556006820160009055600782016000905560088201600090555050600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480610da557610da4613010565b5b6001900381819060005260206000200160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690559055600160026000828254610ded9190612fad565b925050819055507f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa1658433604051610e25929190613080565b60405180910390a180156110c2576000600660008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1660ff161415610f92573373ffffffffffffffffffffffffffffffffffffffff166108fc600660008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101549081150290604051600060405180830381858888f19350505050158015610f16573d6000803e3d6000fd5b50600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549060ff0219169055600182016000905560028201600090556003820160009055600482016000905550506110c1565b600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020849080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555043600660008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206003018190555043600660008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600401819055505b5b50505050505b5b005b600080fd5b3480156110dc57600080fd5b506110e5611a46565b6040516110f291906130b8565b60405180910390f35b34801561110757600080fd5b50611110611a4c565b60405161111d91906130d3565b60405180910390f35b34801561113257600080fd5b5061114d6004803603810190611148919061311f565b611a72565b6040516111629998979695949392919061314c565b60405180910390f35b34801561117757600080fd5b50611180611b60565b60405161118f939291906131d9565b60405180910390f35b3480156111a457600080fd5b506111ad611e8f565b6040516111ba91906130d3565b60405180910390f35b3480156111cf57600080fd5b506111ea60048036038101906111e5919061311f565b611eb3565b6040516111f7919061322b565b60405180910390f35b611208611f4e565b005b34801561121657600080fd5b5061121f612221565b60405161122c91906130b8565b60405180910390f35b34801561124157600080fd5b5061125c60048036038101906112579190613272565b61222e565b60405161126991906130d3565b60405180910390f35b61128c60048036038101906112879190613329565b61227c565b005b34801561129a57600080fd5b506112b560048036038101906112b0919061311f565b6129c3565b6040516112c695949392919061338b565b60405180910390f35b3480156112db57600080fd5b506112e4612a06565b6040516112f191906130b8565b60405180910390f35b34801561130657600080fd5b50611321600480360381019061131c919061311f565b612a0c565b60405161132e91906130d3565b60405180910390f35b34801561134357600080fd5b5061134c612a78565b60405161135991906130b8565b60405180910390f35b34801561136e57600080fd5b5061138960048036038101906113849190613272565b612a84565b60405161139691906130d3565b60405180910390f35b3480156113ab57600080fd5b506113b4612ad2565b6040516113c191906130b8565b60405180910390f35b3480156113d657600080fd5b506113df612ad8565b6040516113ec91906130b8565b60405180910390f35b34801561140157600080fd5b5061141c60048036038101906114179190613272565b612add565b60405161142a929190613489565b60405180910390f35b61144d600480360381019061144891906134b2565b612c61565b005b34801561145b57600080fd5b5061147660048036038101906114719190613272565b612d06565b604051611484929190613489565b60405180910390f35b34801561149957600080fd5b506114b460048036038101906114af919061311f565b612e8a565b6040516114c494939291906134df565b60405180910390f35b600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16146115c557610320600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060154436115b49190612fad565b11156115c4576115c3816115c8565b5b5b50565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701541115611a43576001600360008282546116269190612fad565b925050819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161461187b5780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146119b75781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506119f9565b81600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b43600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206002018190555050505b50565b60035481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60046020528060005260406000206000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060050154908060060154908060070154908060080154905089565b6000806000806001600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050611bb59190612fad565b90506000600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208281548110611c0a57611c09612fe1565b5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1660ff161115611e7d5760006064600660008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1660ff16611cf39190613524565b600660008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010154600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206004015443611d849190612fad565b611d8e9190613524565b611d9891906135ad565b9050600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010154811115611e2a57600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001015490505b8181600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010154955095509550505050611e8a565b8060008094509450945050505b909192565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008073ffffffffffffffffffffffffffffffffffffffff16600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614159050919050565b6000806000611f5b611b60565b809350819450829550505050600082111561221c573373ffffffffffffffffffffffffffffffffffffffff166108fc839081150290604051600060405180830381858888f19350505050158015611fb6573d6000803e3d6000fd5b507ff56207bce501d5c15c703a0203d71486191e363a671ce5f63dbb7c25ff074749833384600660008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001015460405161202e94939291906135de565b60405180910390a181600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160008282546120889190612fad565b9250508190555043600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600401819055506000600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101541161221b57600660008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549060ff021916905560018201600090556002820160009055600382016000905560048201600090555050600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054806121e5576121e4613010565b5b6001900381819060005260206000200160006101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905590555b5b505050565b68056bc75e2d6310000081565b6005602052816000526040600020818154811061224a57600080fd5b906000526020600020016000915091509054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141580156123475750600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16145b801561235b575068056bc75e2d6310000034145b8015612378575060008160ff161480612377575060018160ff16145b5b61238157600080fd5b60405180610120016040528060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff16815260200143815260200160008152602001600081526020016000815250600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060408201518160020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060608201518160030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060808201518160040160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060a0820151816005015560c0820151816006015560e0820151816007015561010082015181600801559050506040518060a001604052808260ff16815260200168056bc75e2d63100000815260200160008152602001600081526020016000815250600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160010155604082015181600201556060820151816003015560808201518160040155905050600073ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146127db5782600460008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b826000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600560008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020839080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506001600260008282546128ce9190612f57565b925050819055508273ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a76400009081150290604051600060405180830381858888f19350505050158015612923573d6000803e3d6000fd5b50670de0b6b3a7640000600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101600082825461297e9190612fad565b925050819055507fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e83836040516129b6929190613682565b60405180910390a1505050565b60066020528060005260406000206000915090508060000160009054906101000a900460ff16908060010154908060020154908060030154908060040154905085565b60025481565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b670de0b6b3a764000081565b60076020528160005260406000208181548110612aa057600080fd5b906000526020600020016000915091509054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b61032081565b606481565b6000612ae7612efc565b6000600760008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480602002602001604051908101604052809291908181526020018280548015612ba857602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311612b5e575b505050505090508051925060005b600581108015612bd05750838582612bce9190612f57565b105b15612c5857818582612be29190612f57565b81518110612bf357612bf2612fe1565b5b6020026020010151838260058110612c0e57612c0d612fe1565b5b602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250508080612c50906136ab565b915050612bb6565b50509250929050565b60008190507f3518abf4c2ea1b253c932187f297fe89ded26f2d747874959ae3df0709f5873481604051612c959190613751565b60405180910390a160008260581b600060158110612cb657612cb5612fe1565b5b1a60f81b60f81c90507fb60e72ccf6d57ab53eb84d7e94a9545806ed7f93c4d5673f11a64f03471e584e81604051612cee91906137fc565b60405180910390a1612d0182338361227c565b505050565b6000612d10612efc565b6000600560008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480602002602001604051908101604052809291908181526020018280548015612dd157602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311612d87575b505050505090508051925060005b600581108015612df95750838582612df79190612f57565b105b15612e8157818582612e0b9190612f57565b81518110612e1c57612e1b612fe1565b5b6020026020010151838260058110612e3757612e36612fe1565b5b602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250508080612e79906136ab565b915050612ddf565b50509250929050565b600080600080670de0b6b3a764000047612ea491906135ad565b935060025492506003549150600560008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905090509193509193565b6040518060a00160405280600590602082028036833780820191505090505090565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000612f6282612f1e565b9150612f6d83612f1e565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115612fa257612fa1612f28565b5b828201905092915050565b6000612fb882612f1e565b9150612fc383612f1e565b925082821015612fd657612fd5612f28565b5b828203905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603160045260246000fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061306a8261303f565b9050919050565b61307a8161305f565b82525050565b60006040820190506130956000830185613071565b6130a26020830184613071565b9392505050565b6130b281612f1e565b82525050565b60006020820190506130cd60008301846130a9565b92915050565b60006020820190506130e86000830184613071565b92915050565b600080fd5b6130fc8161305f565b811461310757600080fd5b50565b600081359050613119816130f3565b92915050565b600060208284031215613135576131346130ee565b5b60006131438482850161310a565b91505092915050565b600061012082019050613162600083018c613071565b61316f602083018b613071565b61317c604083018a613071565b6131896060830189613071565b6131966080830188613071565b6131a360a08301876130a9565b6131b060c08301866130a9565b6131bd60e08301856130a9565b6131cb6101008301846130a9565b9a9950505050505050505050565b60006060820190506131ee6000830186613071565b6131fb60208301856130a9565b61320860408301846130a9565b949350505050565b60008115159050919050565b61322581613210565b82525050565b6000602082019050613240600083018461321c565b92915050565b61324f81612f1e565b811461325a57600080fd5b50565b60008135905061326c81613246565b92915050565b60008060408385031215613289576132886130ee565b5b60006132978582860161310a565b92505060206132a88582860161325d565b9150509250929050565b60006132bd8261303f565b9050919050565b6132cd816132b2565b81146132d857600080fd5b50565b6000813590506132ea816132c4565b92915050565b600060ff82169050919050565b613306816132f0565b811461331157600080fd5b50565b600081359050613323816132fd565b92915050565b600080600060608486031215613342576133416130ee565b5b6000613350868287016132db565b93505060206133618682870161310a565b925050604061337286828701613314565b9150509250925092565b613385816132f0565b82525050565b600060a0820190506133a0600083018861337c565b6133ad60208301876130a9565b6133ba60408301866130a9565b6133c760608301856130a9565b6133d460808301846130a9565b9695505050505050565b600060059050919050565b600081905092915050565b6000819050919050565b6134078161305f565b82525050565b600061341983836133fe565b60208301905092915050565b6000602082019050919050565b61343b816133de565b61344581846133e9565b9250613450826133f4565b8060005b83811015613481578151613468878261340d565b965061347383613425565b925050600181019050613454565b505050505050565b600060c08201905061349e60008301856130a9565b6134ab6020830184613432565b9392505050565b6000602082840312156134c8576134c76130ee565b5b60006134d68482850161325d565b91505092915050565b60006080820190506134f460008301876130a9565b61350160208301866130a9565b61350e60408301856130a9565b61351b60608301846130a9565b95945050505050565b600061352f82612f1e565b915061353a83612f1e565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff048311821515161561357357613572612f28565b5b828202905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006135b882612f1e565b91506135c383612f1e565b9250826135d3576135d261357e565b5b828204905092915050565b60006080820190506135f36000830187613071565b6136006020830186613071565b61360d60408301856130a9565b61361a60608301846130a9565b95945050505050565b6000819050919050565b600061364861364361363e8461303f565b613623565b61303f565b9050919050565b600061365a8261362d565b9050919050565b600061366c8261364f565b9050919050565b61367c81613661565b82525050565b60006040820190506136976000830185613673565b6136a46020830184613071565b9392505050565b60006136b682612f1e565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8214156136e9576136e8612f28565b5b600182019050919050565b600082825260208201905092915050565b7f6e69643a00000000000000000000000000000000000000000000000000000000600082015250565b600061373b6004836136f4565b915061374682613705565b602082019050919050565b6000604082019050818103600083015261376a8161372e565b90506137796020830184613673565b92915050565b7f704f70743a000000000000000000000000000000000000000000000000000000600082015250565b60006137b56005836136f4565b91506137c08261377f565b602082019050919050565b60006137e66137e16137dc846132f0565b613623565b612f1e565b9050919050565b6137f6816137cb565b82525050565b60006040820190508181036000830152613815816137a8565b905061382460208301846137ed565b9291505056fea2646970667358221220a381f1674a78383a111e7dd862f32bdee25c96cce337ea5ff6ef9a258b87499864736f6c634300080a0033
//0x60806040526004361061012d5760003560e01c80636e50d9bf116100ab578063a737b1861161006f578063a737b1861461139f578063a7676366146113ca578063ebc07741146113f5578063f207564e14611433578063f90638a31461144f578063ffdd5cf11461148d576110cb565b80636e50d9bf1461128e57806373b15098146112cf5780638f35a75e146112fa57806393822557146113375780639c40a21d14611362576110cb565b806321887c3d116100f257806321887c3d146111c35780632e64cec11461120057806331deb7e11461120a578063367d5e621461123557806349c107fb14611272576110cb565b8062b54ea6146110d057806304ad33bb146110fb578063189a5a17146111265780631a30b52c1461116b578063200fc3ff14611198576110cb565b366110cb57600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16146107a657600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070154600014156104da576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206007018190555060016003600082825461026e9190612f57565b92505081905550600073ffffffffffffffffffffffffffffffffffffffff16600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461036f573360046000600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610684565b6000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600601541115610683576000600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060154436105759190612fad565b90506103208111156105ce576001600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070181905550610681565b80600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060070160008282546106209190612f57565b9250508190555080600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060080160008282546106799190612f57565b925050819055505b505b5b43600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060181905550610736600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166114cd565b6107a1600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff166114cd565b6110c9565b6000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905011156110c85760006001600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805490506108429190612fad565b90506000600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020828154811061089757610896612fe1565b5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16141561096057600080fd5b610969816115c8565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614610aed5780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610ba75781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610be8565b816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600080600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060050154119050600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556001820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556002820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556003820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690556004820160006101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905560058201600090556006820160009055600782016000905560088201600090555050600560003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480610da557610da4613010565b5b6001900381819060005260206000200160006101000a81549073ffffffffffffffffffffffffffffffffffffffff02191690559055600160026000828254610ded9190612fad565b925050819055507f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa1658433604051610e25929190613080565b60405180910390a180156110c2576000600660008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1660ff161415610f92573373ffffffffffffffffffffffffffffffffffffffff166108fc600660008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101549081150290604051600060405180830381858888f19350505050158015610f16573d6000803e3d6000fd5b50600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549060ff0219169055600182016000905560028201600090556003820160009055600482016000905550506110c1565b600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020849080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555043600660008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206003018190555043600660008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600401819055505b5b50505050505b5b005b600080fd5b3480156110dc57600080fd5b506110e5611a46565b6040516110f291906130b8565b60405180910390f35b34801561110757600080fd5b50611110611a4c565b60405161111d91906130d3565b60405180910390f35b34801561113257600080fd5b5061114d6004803603810190611148919061311f565b611a72565b6040516111629998979695949392919061314c565b60405180910390f35b34801561117757600080fd5b50611180611b60565b60405161118f939291906131d9565b60405180910390f35b3480156111a457600080fd5b506111ad611e8f565b6040516111ba91906130d3565b60405180910390f35b3480156111cf57600080fd5b506111ea60048036038101906111e5919061311f565b611eb3565b6040516111f7919061322b565b60405180910390f35b611208611f4e565b005b34801561121657600080fd5b5061121f612221565b60405161122c91906130b8565b60405180910390f35b34801561124157600080fd5b5061125c60048036038101906112579190613272565b61222e565b60405161126991906130d3565b60405180910390f35b61128c60048036038101906112879190613329565b61227c565b005b34801561129a57600080fd5b506112b560048036038101906112b0919061311f565b6129c3565b6040516112c695949392919061338b565b60405180910390f35b3480156112db57600080fd5b506112e4612a06565b6040516112f191906130b8565b60405180910390f35b34801561130657600080fd5b50611321600480360381019061131c919061311f565b612a0c565b60405161132e91906130d3565b60405180910390f35b34801561134357600080fd5b5061134c612a78565b60405161135991906130b8565b60405180910390f35b34801561136e57600080fd5b5061138960048036038101906113849190613272565b612a84565b60405161139691906130d3565b60405180910390f35b3480156113ab57600080fd5b506113b4612ad2565b6040516113c191906130b8565b60405180910390f35b3480156113d657600080fd5b506113df612ad8565b6040516113ec91906130b8565b60405180910390f35b34801561140157600080fd5b5061141c60048036038101906114179190613272565b612add565b60405161142a929190613489565b60405180910390f35b61144d600480360381019061144891906134b2565b612c61565b005b34801561145b57600080fd5b5061147660048036038101906114719190613272565b612d06565b604051611484929190613489565b60405180910390f35b34801561149957600080fd5b506114b460048036038101906114af919061311f565b612e8a565b6040516114c494939291906134df565b60405180910390f35b600460008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16146115c557610320600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060060154436115b49190612fad565b11156115c4576115c3816115c8565b5b5b50565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701541115611a43576001600360008282546116269190612fad565b925050819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600701819055506000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161461187b5780600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146119b75781600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506119f9565b81600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b43600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206002018190555050505b50565b60035481565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60046020528060005260406000206000915090508060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060030160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060050154908060060154908060070154908060080154905089565b6000806000806001600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002080549050611bb59190612fad565b90506000600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208281548110611c0a57611c09612fe1565b5b9060005260206000200160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690506000600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1660ff161115611e7d5760006064600660008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1660ff16611cf39190613524565b600660008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010154600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206004015443611d849190612fad565b611d8e9190613524565b611d9891906135ad565b9050600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010154811115611e2a57600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001015490505b8181600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010154955095509550505050611e8a565b8060008094509450945050505b909192565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008073ffffffffffffffffffffffffffffffffffffffff16600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614159050919050565b6000806000611f5b611b60565b809350819450829550505050600082111561221c573373ffffffffffffffffffffffffffffffffffffffff166108fc839081150290604051600060405180830381858888f19350505050158015611fb6573d6000803e3d6000fd5b507ff56207bce501d5c15c703a0203d71486191e363a671ce5f63dbb7c25ff074749833384600660008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206001015460405161202e94939291906135de565b60405180910390a181600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160008282546120889190612fad565b9250508190555043600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600401819055506000600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101541161221b57600660008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600080820160006101000a81549060ff021916905560018201600090556002820160009055600382016000905560048201600090555050600760003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054806121e5576121e4613010565b5b6001900381819060005260206000200160006101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905590555b5b505050565b68056bc75e2d6310000081565b6005602052816000526040600020818154811061224a57600080fd5b906000526020600020016000915091509054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141580156123475750600460008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff16145b801561235b575068056bc75e2d6310000034145b8015612378575060008160ff161480612377575060018160ff16145b5b61238157600080fd5b60405180610120016040528060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff1681526020018373ffffffffffffffffffffffffffffffffffffffff16815260200143815260200160008152602001600081526020016000815250600460008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060408201518160020160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060608201518160030160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060808201518160040160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060a0820151816005015560c0820151816006015560e0820151816007015561010082015181600801559050506040518060a001604052808260ff16815260200168056bc75e2d63100000815260200160008152602001600081526020016000815250600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160010155604082015181600201556060820151816003015560808201518160040155905050600073ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146127db5782600460008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505b826000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600560008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020839080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506001600260008282546128ce9190612f57565b925050819055508273ffffffffffffffffffffffffffffffffffffffff166108fc670de0b6b3a76400009081150290604051600060405180830381858888f19350505050158015612923573d6000803e3d6000fd5b50670de0b6b3a7640000600660008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600101600082825461297e9190612fad565b925050819055507fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e83836040516129b6929190613682565b60405180910390a1505050565b60066020528060005260406000206000915090508060000160009054906101000a900460ff16908060010154908060020154908060030154908060040154905085565b60025481565b6000600460008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060040160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b670de0b6b3a764000081565b60076020528160005260406000208181548110612aa057600080fd5b906000526020600020016000915091509054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b61032081565b606481565b6000612ae7612efc565b6000600760008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480602002602001604051908101604052809291908181526020018280548015612ba857602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311612b5e575b505050505090508051925060005b600581108015612bd05750838582612bce9190612f57565b105b15612c5857818582612be29190612f57565b81518110612bf357612bf2612fe1565b5b6020026020010151838260058110612c0e57612c0d612fe1565b5b602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250508080612c50906136ab565b915050612bb6565b50509250929050565b60008190507f3518abf4c2ea1b253c932187f297fe89ded26f2d747874959ae3df0709f5873481604051612c959190613751565b60405180910390a160008260581b600060158110612cb657612cb5612fe1565b5b1a60f81b60f81c90507fb60e72ccf6d57ab53eb84d7e94a9545806ed7f93c4d5673f11a64f03471e584e81604051612cee91906137fc565b60405180910390a1612d0182338361227c565b505050565b6000612d10612efc565b6000600560008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020805480602002602001604051908101604052809291908181526020018280548015612dd157602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019060010190808311612d87575b505050505090508051925060005b600581108015612df95750838582612df79190612f57565b105b15612e8157818582612e0b9190612f57565b81518110612e1c57612e1b612fe1565b5b6020026020010151838260058110612e3757612e36612fe1565b5b602002019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250508080612e79906136ab565b915050612ddf565b50509250929050565b600080600080670de0b6b3a764000047612ea491906135ad565b935060025492506003549150600560008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208054905090509193509193565b6040518060a00160405280600590602082028036833780820191505090505090565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000612f6282612f1e565b9150612f6d83612f1e565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115612fa257612fa1612f28565b5b828201905092915050565b6000612fb882612f1e565b9150612fc383612f1e565b925082821015612fd657612fd5612f28565b5b828203905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603160045260246000fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061306a8261303f565b9050919050565b61307a8161305f565b82525050565b60006040820190506130956000830185613071565b6130a26020830184613071565b9392505050565b6130b281612f1e565b82525050565b60006020820190506130cd60008301846130a9565b92915050565b60006020820190506130e86000830184613071565b92915050565b600080fd5b6130fc8161305f565b811461310757600080fd5b50565b600081359050613119816130f3565b92915050565b600060208284031215613135576131346130ee565b5b60006131438482850161310a565b91505092915050565b600061012082019050613162600083018c613071565b61316f602083018b613071565b61317c604083018a613071565b6131896060830189613071565b6131966080830188613071565b6131a360a08301876130a9565b6131b060c08301866130a9565b6131bd60e08301856130a9565b6131cb6101008301846130a9565b9a9950505050505050505050565b60006060820190506131ee6000830186613071565b6131fb60208301856130a9565b61320860408301846130a9565b949350505050565b60008115159050919050565b61322581613210565b82525050565b6000602082019050613240600083018461321c565b92915050565b61324f81612f1e565b811461325a57600080fd5b50565b60008135905061326c81613246565b92915050565b60008060408385031215613289576132886130ee565b5b60006132978582860161310a565b92505060206132a88582860161325d565b9150509250929050565b60006132bd8261303f565b9050919050565b6132cd816132b2565b81146132d857600080fd5b50565b6000813590506132ea816132c4565b92915050565b600060ff82169050919050565b613306816132f0565b811461331157600080fd5b50565b600081359050613323816132fd565b92915050565b600080600060608486031215613342576133416130ee565b5b6000613350868287016132db565b93505060206133618682870161310a565b925050604061337286828701613314565b9150509250925092565b613385816132f0565b82525050565b600060a0820190506133a0600083018861337c565b6133ad60208301876130a9565b6133ba60408301866130a9565b6133c760608301856130a9565b6133d460808301846130a9565b9695505050505050565b600060059050919050565b600081905092915050565b6000819050919050565b6134078161305f565b82525050565b600061341983836133fe565b60208301905092915050565b6000602082019050919050565b61343b816133de565b61344581846133e9565b9250613450826133f4565b8060005b83811015613481578151613468878261340d565b965061347383613425565b925050600181019050613454565b505050505050565b600060c08201905061349e60008301856130a9565b6134ab6020830184613432565b9392505050565b6000602082840312156134c8576134c76130ee565b5b60006134d68482850161325d565b91505092915050565b60006080820190506134f460008301876130a9565b61350160208301866130a9565b61350e60408301856130a9565b61351b60608301846130a9565b95945050505050565b600061352f82612f1e565b915061353a83612f1e565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff048311821515161561357357613572612f28565b5b828202905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b60006135b882612f1e565b91506135c383612f1e565b9250826135d3576135d261357e565b5b828204905092915050565b60006080820190506135f36000830187613071565b6136006020830186613071565b61360d60408301856130a9565b61361a60608301846130a9565b95945050505050565b6000819050919050565b600061364861364361363e8461303f565b613623565b61303f565b9050919050565b600061365a8261362d565b9050919050565b600061366c8261364f565b9050919050565b61367c81613661565b82525050565b60006040820190506136976000830185613673565b6136a46020830184613071565b9392505050565b60006136b682612f1e565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8214156136e9576136e8612f28565b5b600182019050919050565b600082825260208201905092915050565b7f6e69643a00000000000000000000000000000000000000000000000000000000600082015250565b600061373b6004836136f4565b915061374682613705565b602082019050919050565b6000604082019050818103600083015261376a8161372e565b90506137796020830184613673565b92915050565b7f704f70743a000000000000000000000000000000000000000000000000000000600082015250565b60006137b56005836136f4565b91506137c08261377f565b602082019050919050565b60006137e66137e16137dc846132f0565b613623565b612f1e565b9050919050565b6137f6816137cb565b82525050565b60006040820190508181036000830152613815816137a8565b905061382460208301846137ed565b9291505056fea2646970667358221220a381f1674a78383a111e7dd862f32bdee25c96cce337ea5ff6ef9a258b87499864736f6c634300080a0033

//0x4420e4860000000000000000000000008a6b1dc6d606a151ce932ae55479ea9eb67e5805
//0x0000000000000000000000008a6b1dc6d606a151ce932ae55479ea9eb67e5805
//0x4420e4860000000000000000000000018a6b1dc6d606a151ce932ae55479ea9eb67e5805
