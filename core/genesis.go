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
		Code:    hexutil.MustDecode("0x6080604052600436106101345760003560e01c8063677321da116100ab5780638f35a75e1161006f5780638f35a75e1461059757806393822557146105d3578063a8365f61146105ef578063c55ae72f14610604578063e331c43914610624578063eb5821861461063a57610134565b8063677321da14610518578063684c26111461052b57806369438d7b1461054b57806370d1d0311461056b57806373b150981461058157610134565b8063200fc3ff116100fd578063200fc3ff1461044457806321887c3d1461046457806331deb7e1146104ba5780634420e486146104d0578063551619131461031f5780635a9b0b89146104e357610134565b8062b54ea6146102a957806304ad33bb146102d25780631209f7ed1461030a578063189a5a17146103215780631f3c99c31461042f575b34801561014057600080fd5b5033600090815260076020526040902060040154600160a01b900460ff166001146101a45760405162461bcd60e51b815260206004820152600f60248201526e496e76616c69642073656e6465722160881b60448201526064015b60405180910390fd5b33600090815260076020526040902060060154156101f65760405162461bcd60e51b815260206004820152600f60248201526e416c7265616479206f6e6c696e652160881b604482015260640161019b565b33600090815260076020526040812043600690910155600380546001929061021f9084906113b1565b90915550506001546001600160a01b031615610263576001546001600160a01b0316600090815260076020526040902060030180546001600160a01b031916331790555b600180543360008181526007602052604090206002810180546001600160a01b039094166001600160a01b03199485161790556003018054831690558254909116179055005b3480156102b557600080fd5b506102bf60035481565b6040519081526020015b60405180910390f35b3480156102de57600080fd5b506001546102f2906001600160a01b031681565b6040516001600160a01b0390911681526020016102c9565b34801561031657600080fd5b5061031f610670565b005b34801561032d57600080fd5b506103b461033c3660046113de565b600760208190526000918252604090912080546001820154600283015460038401546004850154600586015460068701549787015460088801546009890154600a8a0154600b909a01546001600160a01b03998a169b988a169a978a16999687169896861697600160a01b90960460ff16969495908d565b604080516001600160a01b039e8f1681529c8e1660208e01529a8d169a8c019a909a52978b1660608b015299909516608089015260ff90931660a088015260c087019190915260e08601526101008501526101208401526101408301939093526101608201929092526101808101919091526101a0016102c9565b34801561043b57600080fd5b5061031f610852565b34801561045057600080fd5b506000546102f2906001600160a01b031681565b34801561047057600080fd5b506104aa61047f3660046113de565b6001600160a01b0316600090815260076020526040902060040154600160a01b900460ff1660011490565b60405190151581526020016102c9565b3480156104c657600080fd5b506102bf60065481565b61031f6104de3660046113de565b610a1e565b3480156104ef57600080fd5b506104f8610a2b565b6040805194855260208501939093529183015260608201526080016102c9565b61031f610526366004611402565b610a59565b34801561053757600080fd5b506104f86105463660046113de565b610e44565b34801561055757600080fd5b506102bf6105663660046113de565b610f28565b34801561057757600080fd5b506102bf60055481565b34801561058d57600080fd5b506102bf60025481565b3480156105a357600080fd5b506102f26105b23660046113de565b6001600160a01b039081166000908152600760205260409020600401541690565b3480156105df57600080fd5b506102bf670de0b6b3a764000081565b3480156105fb57600080fd5b5061031f611007565b34801561061057600080fd5b5061031f61061f3660046113de565b6110ae565b34801561063057600080fd5b506102bf60045481565b34801561064657600080fd5b506102f26106553660046113de565b6008602052600090815260409020546001600160a01b031681565b336000908152600860205260409020546001600160a01b0316806106c85760405162461bcd60e51b815260206004820152600f60248201526e446f6e27742068617665206e6f646560881b604482015260640161019b565b6001600160a01b038116600090815260076020819052604090912001541580159061071857506001600160a01b038116600090815260076020526040902060040154600160a01b900460ff166002145b6107575760405162461bcd60e51b815260206004820152601060248201526f139bdd081e595d081c995b19585cd95960821b604482015260640161019b565b6001600160a01b0381166000908152600760208190526040909120015443116107c25760405162461bcd60e51b815260206004820152601960248201527f496e76616c696420626c6f636b4c617374576974686472617700000000000000604482015260640161019b565b60006107cd82610f28565b6001600160a01b0383166000908152600760205260408120600901805492935083929091906107fd9084906113b1565b90915550506001600160a01b03821660009081526007602081905260408083204392019190915551339183156108fc02918491818181858888f1935050505015801561084d573d6000803e3d6000fd5b505050565b336000908152600860209081526040808320546001600160a01b031680845260079092529091206004015460ff600160a01b909104166001146108cc5760405162461bcd60e51b8152602060048201526012602482015271486173206265656e2072656c65617365642160701b604482015260640161019b565b6108d581611232565b6001600160a01b038082166000908152600760205260409020805460019091015490821691168115610933576001600160a01b03828116600090815260076020526040902060010180546001600160a01b0319169183169190911790555b6001600160a01b03811615610975576001600160a01b03818116600090815260076020526040902080546001600160a01b031916918416919091179055610991565b600080546001600160a01b0319166001600160a01b0384161790555b6001600460008282546109a491906113b1565b90915550506001600160a01b03831660008181526007602081815260409283902043928101929092556004909101805460ff60a01b1916600160a11b179055815192835233908301527f39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa16591015b60405180910390a1505050565b610a288133610a59565b50565b6000808080610a42670de0b6b3a76400004761143b565b935060025492506003549150600454905090919293565b6001600160a01b038216610a9e5760405162461bcd60e51b815260206004820152600c60248201526b496e76616c6964206e69642160a01b604482015260640161019b565b6001600160a01b038216600090815260076020526040902060040154600160a01b900460ff1615610b115760405162461bcd60e51b815260206004820152601c60248201527f546865206e696420686173206265656e20726567697374657265642100000000604482015260640161019b565b6001600160a01b038082166000908152600860205260409020541615610b795760405162461bcd60e51b815260206004820152601d60248201527f546865206f776e6572206173206265656e207265676973746572656421000000604482015260640161019b565b6006543414610bbe5760405162461bcd60e51b8152602060048201526011602482015270496e76616c6964206e6f6465436f73742160781b604482015260640161019b565b604080516101a081018252600080546001600160a01b03908116835260208301829052928201819052606082018190529183166080820152600160a08201524360c082015260e08101829052610100810191909152600654610120820190610c2f90670de0b6b3a76400009061145d565b815260006020808301829052604080840183905260609384018390526001600160a01b0380881684526007808452828520875181549084166001600160a01b03199182161782559488015160018201805491851691871691909117905592870151600284018054918416918616919091179055948601516003830180549183169190941617909255608085015160048201805460a088015160ff16600160a01b026001600160a81b03199091169285169290921791909117905560c0850151600582015560e085015160068201556101008501519381019390935561012084015160088401556101408401516009840155610160840151600a84015561018090930151600b90920191909155541615610d7657600080546001600160a01b0390811682526007602052604090912060010180546001600160a01b0319169184169190911790555b600080546001600160a01b038085166001600160a01b031992831681178455908416835260086020526040832080549092161790556002805460019290610dbe9084906113b1565b90915550506040516001600160a01b03831690600090670de0b6b3a76400009082818181858883f19350505050158015610dfc573d6000803e3d6000fd5b50604080516001600160a01b038085168252831660208201527fb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e910160405180910390a15050565b6001600160a01b038181166000908152600860209081526040808320549093168083526007909152918120600a81015460049091015490928291829190600160a01b900460ff1660021415610f2057610e9c81610f28565b6001600160a01b038216600090815260076020526040902060098101546008909101549195508591610ece919061145d565b610ed8919061145d565b6005546001600160a01b03831660009081526007602052604081206008015492955091610f05919061143b565b9050610f11818561143b565b610f1c906003611474565b9250505b509193509193565b6001600160a01b038116600090815260076020526040812060040154600160a01b900460ff16600214610f5d57506000919050565b6001600160a01b038216600090815260076020819052604082200154610f83904361145d565b6005546001600160a01b03851660009081526007602052604081206008015492935091610fb0919061143b565b90506000610fbe8284611474565b6001600160a01b038616600090815260076020526040812060098101546008909101549293509091610ff0919061145d565b905080821115610ffe578091505b50949350505050565b336000908152600860205260409020546001600160a01b03168061105f5760405162461bcd60e51b815260206004820152600f60248201526e446f6e27742068617665206e6f646560881b604482015260640161019b565b6001600160a01b038116600090815260076020526040808220600a0180549083905590519091339183156108fc0291849190818181858888f1935050505015801561084d573d6000803e3d6000fd5b6110b661135f565b6110be61137d565b6001600160a01b03831682523360208084019190915281604084600084600019f16110e857600080fd5b805160011415611137578051156111325760405162461bcd60e51b815260206004820152600e60248201526d496e76616c696420696e7075742160901b604482015260640161019b565b6111f4565b805160021415611190578051156111325760405162461bcd60e51b815260206004820152601e60248201527f5468652063616c6c6572206d757374206265206120636f6e7472616374210000604482015260640161019b565b8051600314156111f4578051156111f45760405162461bcd60e51b815260206004820152602260248201527f54686520636f6e747261637420686173206265656e20696e697469616c697a65604482015261642160f01b606482015260840161019b565b604080516001600160a01b03851681523360208201527fcef34eae8f50e9e7369f1fe0973242562fc88687ca07b1e856397986cac6d3ad9101610a11565b6001600160a01b03811660009081526007602052604090206006015415610a2857600160036000828254611266919061145d565b90915550506001600160a01b03808216600090815260076020526040812060068101919091556002810154600390910154908216911681156112e6576001600160a01b0380831660009081526007602052604080822060030180548486166001600160a01b03199182161790915592861682529020600201805490911690555b6001600160a01b0381161561133d576001600160a01b0380821660009081526007602052604080822060020180548487166001600160a01b0319918216179091559286168252902060030180549091169055505050565b600180546001600160a01b0384166001600160a01b0319909116179055505050565b60405180604001604052806002906020820280368337509192915050565b60405180602001604052806001906020820280368337509192915050565b634e487b7160e01b600052601160045260246000fd5b600082198211156113c4576113c461139b565b500190565b6001600160a01b0381168114610a2857600080fd5b6000602082840312156113f057600080fd5b81356113fb816113c9565b9392505050565b6000806040838503121561141557600080fd5b8235611420816113c9565b91506020830135611430816113c9565b809150509250929050565b60008261145857634e487b7160e01b600052601260045260246000fd5b500490565b60008282101561146f5761146f61139b565b500390565b600081600019048311821515161561148e5761148e61139b565b50029056fea264697066735822122092016d97e4e88b2bbb015ae0972d97973720ad8ceb939be3afa0a814379ec8d364736f6c634300080b0033"),
	}
}
