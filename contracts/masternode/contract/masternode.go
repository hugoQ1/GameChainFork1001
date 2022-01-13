// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package contract

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// ContractMetaData contains all meta data concerning the Contract contract.
var ContractMetaData = &bind.MetaData{
	ABI: "[{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"src\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"dst\",\"type\":\"address\"}],\"name\":\"fork\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"nid\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"join\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"nid\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"quit\",\"type\":\"event\"},{\"stateMutability\":\"nonpayable\",\"type\":\"fallback\"},{\"inputs\":[],\"name\":\"baseCost\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"charge\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"countOnlineNode\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"countReleasedNode\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"countTotalNode\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"src\",\"type\":\"address\"}],\"name\":\"forkContractData\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getInfo\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"totalBalance\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"totalNodes\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"onlineNodes\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"releaseNodes\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"nid\",\"type\":\"address\"}],\"name\":\"getInvestor\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"getReleaseInfo\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"balanceMint\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"pendingAsset\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"lockedAsset\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"releaseTime\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"nid\",\"type\":\"address\"}],\"name\":\"has\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"investor2nid\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"lastNode\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"lastOnlineNode\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"logout\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"nodeCost\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"nodes\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"preNode\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"nextNode\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"preOnlineNode\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"nextOnlineNode\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"investor\",\"type\":\"address\"},{\"internalType\":\"uint8\",\"name\":\"status\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"blockRegister\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"blockOnline\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"blockLastWithdraw\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"balancePledge\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"balancePledgeDebt\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"balanceMint\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"totalMint\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"nid\",\"type\":\"address\"}],\"name\":\"pendingCalc\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"addresspayable\",\"name\":\"nid\",\"type\":\"address\"}],\"name\":\"register\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"addresspayable\",\"name\":\"nid\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"}],\"name\":\"registerAgent\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"releaseBlocks\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"withdrawMint\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"withdrawPledge\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]",
	Bin: "0x00",
}

// ContractABI is the input ABI used to generate the binding from.
// Deprecated: Use ContractMetaData.ABI instead.
var ContractABI = ContractMetaData.ABI

// ContractBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use ContractMetaData.Bin instead.
var ContractBin = ContractMetaData.Bin

// DeployContract deploys a new Ethereum contract, binding an instance of Contract to it.
func DeployContract(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Contract, error) {
	parsed, err := ContractMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(ContractBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// Contract is an auto generated Go binding around an Ethereum contract.
type Contract struct {
	ContractCaller     // Read-only binding to the contract
	ContractTransactor // Write-only binding to the contract
	ContractFilterer   // Log filterer for contract events
}

// ContractCaller is an auto generated read-only Go binding around an Ethereum contract.
type ContractCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ContractTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ContractFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ContractSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ContractSession struct {
	Contract     *Contract         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ContractCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ContractCallerSession struct {
	Contract *ContractCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// ContractTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ContractTransactorSession struct {
	Contract     *ContractTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// ContractRaw is an auto generated low-level Go binding around an Ethereum contract.
type ContractRaw struct {
	Contract *Contract // Generic contract binding to access the raw methods on
}

// ContractCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ContractCallerRaw struct {
	Contract *ContractCaller // Generic read-only contract binding to access the raw methods on
}

// ContractTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ContractTransactorRaw struct {
	Contract *ContractTransactor // Generic write-only contract binding to access the raw methods on
}

// NewContract creates a new instance of Contract, bound to a specific deployed contract.
func NewContract(address common.Address, backend bind.ContractBackend) (*Contract, error) {
	contract, err := bindContract(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Contract{ContractCaller: ContractCaller{contract: contract}, ContractTransactor: ContractTransactor{contract: contract}, ContractFilterer: ContractFilterer{contract: contract}}, nil
}

// NewContractCaller creates a new read-only instance of Contract, bound to a specific deployed contract.
func NewContractCaller(address common.Address, caller bind.ContractCaller) (*ContractCaller, error) {
	contract, err := bindContract(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ContractCaller{contract: contract}, nil
}

// NewContractTransactor creates a new write-only instance of Contract, bound to a specific deployed contract.
func NewContractTransactor(address common.Address, transactor bind.ContractTransactor) (*ContractTransactor, error) {
	contract, err := bindContract(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ContractTransactor{contract: contract}, nil
}

// NewContractFilterer creates a new log filterer instance of Contract, bound to a specific deployed contract.
func NewContractFilterer(address common.Address, filterer bind.ContractFilterer) (*ContractFilterer, error) {
	contract, err := bindContract(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ContractFilterer{contract: contract}, nil
}

// bindContract binds a generic wrapper to an already deployed contract.
func bindContract(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ContractABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.ContractCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.ContractTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Contract *ContractCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Contract.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Contract *ContractTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Contract *ContractTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Contract.Contract.contract.Transact(opts, method, params...)
}

// BaseCost is a free data retrieval call binding the contract method 0x93822557.
//
// Solidity: function baseCost() view returns(uint256)
func (_Contract *ContractCaller) BaseCost(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "baseCost")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BaseCost is a free data retrieval call binding the contract method 0x93822557.
//
// Solidity: function baseCost() view returns(uint256)
func (_Contract *ContractSession) BaseCost() (*big.Int, error) {
	return _Contract.Contract.BaseCost(&_Contract.CallOpts)
}

// BaseCost is a free data retrieval call binding the contract method 0x93822557.
//
// Solidity: function baseCost() view returns(uint256)
func (_Contract *ContractCallerSession) BaseCost() (*big.Int, error) {
	return _Contract.Contract.BaseCost(&_Contract.CallOpts)
}

// CountOnlineNode is a free data retrieval call binding the contract method 0x00b54ea6.
//
// Solidity: function countOnlineNode() view returns(uint256)
func (_Contract *ContractCaller) CountOnlineNode(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "countOnlineNode")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// CountOnlineNode is a free data retrieval call binding the contract method 0x00b54ea6.
//
// Solidity: function countOnlineNode() view returns(uint256)
func (_Contract *ContractSession) CountOnlineNode() (*big.Int, error) {
	return _Contract.Contract.CountOnlineNode(&_Contract.CallOpts)
}

// CountOnlineNode is a free data retrieval call binding the contract method 0x00b54ea6.
//
// Solidity: function countOnlineNode() view returns(uint256)
func (_Contract *ContractCallerSession) CountOnlineNode() (*big.Int, error) {
	return _Contract.Contract.CountOnlineNode(&_Contract.CallOpts)
}

// CountReleasedNode is a free data retrieval call binding the contract method 0xe331c439.
//
// Solidity: function countReleasedNode() view returns(uint256)
func (_Contract *ContractCaller) CountReleasedNode(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "countReleasedNode")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// CountReleasedNode is a free data retrieval call binding the contract method 0xe331c439.
//
// Solidity: function countReleasedNode() view returns(uint256)
func (_Contract *ContractSession) CountReleasedNode() (*big.Int, error) {
	return _Contract.Contract.CountReleasedNode(&_Contract.CallOpts)
}

// CountReleasedNode is a free data retrieval call binding the contract method 0xe331c439.
//
// Solidity: function countReleasedNode() view returns(uint256)
func (_Contract *ContractCallerSession) CountReleasedNode() (*big.Int, error) {
	return _Contract.Contract.CountReleasedNode(&_Contract.CallOpts)
}

// CountTotalNode is a free data retrieval call binding the contract method 0x73b15098.
//
// Solidity: function countTotalNode() view returns(uint256)
func (_Contract *ContractCaller) CountTotalNode(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "countTotalNode")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// CountTotalNode is a free data retrieval call binding the contract method 0x73b15098.
//
// Solidity: function countTotalNode() view returns(uint256)
func (_Contract *ContractSession) CountTotalNode() (*big.Int, error) {
	return _Contract.Contract.CountTotalNode(&_Contract.CallOpts)
}

// CountTotalNode is a free data retrieval call binding the contract method 0x73b15098.
//
// Solidity: function countTotalNode() view returns(uint256)
func (_Contract *ContractCallerSession) CountTotalNode() (*big.Int, error) {
	return _Contract.Contract.CountTotalNode(&_Contract.CallOpts)
}

// GetInfo is a free data retrieval call binding the contract method 0x5a9b0b89.
//
// Solidity: function getInfo() view returns(uint256 totalBalance, uint256 totalNodes, uint256 onlineNodes, uint256 releaseNodes)
func (_Contract *ContractCaller) GetInfo(opts *bind.CallOpts) (struct {
	TotalBalance *big.Int
	TotalNodes   *big.Int
	OnlineNodes  *big.Int
	ReleaseNodes *big.Int
}, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getInfo")

	outstruct := new(struct {
		TotalBalance *big.Int
		TotalNodes   *big.Int
		OnlineNodes  *big.Int
		ReleaseNodes *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.TotalBalance = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.TotalNodes = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.OnlineNodes = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	outstruct.ReleaseNodes = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// GetInfo is a free data retrieval call binding the contract method 0x5a9b0b89.
//
// Solidity: function getInfo() view returns(uint256 totalBalance, uint256 totalNodes, uint256 onlineNodes, uint256 releaseNodes)
func (_Contract *ContractSession) GetInfo() (struct {
	TotalBalance *big.Int
	TotalNodes   *big.Int
	OnlineNodes  *big.Int
	ReleaseNodes *big.Int
}, error) {
	return _Contract.Contract.GetInfo(&_Contract.CallOpts)
}

// GetInfo is a free data retrieval call binding the contract method 0x5a9b0b89.
//
// Solidity: function getInfo() view returns(uint256 totalBalance, uint256 totalNodes, uint256 onlineNodes, uint256 releaseNodes)
func (_Contract *ContractCallerSession) GetInfo() (struct {
	TotalBalance *big.Int
	TotalNodes   *big.Int
	OnlineNodes  *big.Int
	ReleaseNodes *big.Int
}, error) {
	return _Contract.Contract.GetInfo(&_Contract.CallOpts)
}

// GetInvestor is a free data retrieval call binding the contract method 0x8f35a75e.
//
// Solidity: function getInvestor(address nid) view returns(address)
func (_Contract *ContractCaller) GetInvestor(opts *bind.CallOpts, nid common.Address) (common.Address, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getInvestor", nid)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetInvestor is a free data retrieval call binding the contract method 0x8f35a75e.
//
// Solidity: function getInvestor(address nid) view returns(address)
func (_Contract *ContractSession) GetInvestor(nid common.Address) (common.Address, error) {
	return _Contract.Contract.GetInvestor(&_Contract.CallOpts, nid)
}

// GetInvestor is a free data retrieval call binding the contract method 0x8f35a75e.
//
// Solidity: function getInvestor(address nid) view returns(address)
func (_Contract *ContractCallerSession) GetInvestor(nid common.Address) (common.Address, error) {
	return _Contract.Contract.GetInvestor(&_Contract.CallOpts, nid)
}

// GetReleaseInfo is a free data retrieval call binding the contract method 0x684c2611.
//
// Solidity: function getReleaseInfo(address addr) view returns(uint256 balanceMint, uint256 pendingAsset, uint256 lockedAsset, uint256 releaseTime)
func (_Contract *ContractCaller) GetReleaseInfo(opts *bind.CallOpts, addr common.Address) (struct {
	BalanceMint  *big.Int
	PendingAsset *big.Int
	LockedAsset  *big.Int
	ReleaseTime  *big.Int
}, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getReleaseInfo", addr)

	outstruct := new(struct {
		BalanceMint  *big.Int
		PendingAsset *big.Int
		LockedAsset  *big.Int
		ReleaseTime  *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.BalanceMint = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.PendingAsset = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.LockedAsset = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	outstruct.ReleaseTime = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// GetReleaseInfo is a free data retrieval call binding the contract method 0x684c2611.
//
// Solidity: function getReleaseInfo(address addr) view returns(uint256 balanceMint, uint256 pendingAsset, uint256 lockedAsset, uint256 releaseTime)
func (_Contract *ContractSession) GetReleaseInfo(addr common.Address) (struct {
	BalanceMint  *big.Int
	PendingAsset *big.Int
	LockedAsset  *big.Int
	ReleaseTime  *big.Int
}, error) {
	return _Contract.Contract.GetReleaseInfo(&_Contract.CallOpts, addr)
}

// GetReleaseInfo is a free data retrieval call binding the contract method 0x684c2611.
//
// Solidity: function getReleaseInfo(address addr) view returns(uint256 balanceMint, uint256 pendingAsset, uint256 lockedAsset, uint256 releaseTime)
func (_Contract *ContractCallerSession) GetReleaseInfo(addr common.Address) (struct {
	BalanceMint  *big.Int
	PendingAsset *big.Int
	LockedAsset  *big.Int
	ReleaseTime  *big.Int
}, error) {
	return _Contract.Contract.GetReleaseInfo(&_Contract.CallOpts, addr)
}

// Has is a free data retrieval call binding the contract method 0x21887c3d.
//
// Solidity: function has(address nid) view returns(bool)
func (_Contract *ContractCaller) Has(opts *bind.CallOpts, nid common.Address) (bool, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "has", nid)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Has is a free data retrieval call binding the contract method 0x21887c3d.
//
// Solidity: function has(address nid) view returns(bool)
func (_Contract *ContractSession) Has(nid common.Address) (bool, error) {
	return _Contract.Contract.Has(&_Contract.CallOpts, nid)
}

// Has is a free data retrieval call binding the contract method 0x21887c3d.
//
// Solidity: function has(address nid) view returns(bool)
func (_Contract *ContractCallerSession) Has(nid common.Address) (bool, error) {
	return _Contract.Contract.Has(&_Contract.CallOpts, nid)
}

// Investor2nid is a free data retrieval call binding the contract method 0xeb582186.
//
// Solidity: function investor2nid(address ) view returns(address)
func (_Contract *ContractCaller) Investor2nid(opts *bind.CallOpts, arg0 common.Address) (common.Address, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "investor2nid", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Investor2nid is a free data retrieval call binding the contract method 0xeb582186.
//
// Solidity: function investor2nid(address ) view returns(address)
func (_Contract *ContractSession) Investor2nid(arg0 common.Address) (common.Address, error) {
	return _Contract.Contract.Investor2nid(&_Contract.CallOpts, arg0)
}

// Investor2nid is a free data retrieval call binding the contract method 0xeb582186.
//
// Solidity: function investor2nid(address ) view returns(address)
func (_Contract *ContractCallerSession) Investor2nid(arg0 common.Address) (common.Address, error) {
	return _Contract.Contract.Investor2nid(&_Contract.CallOpts, arg0)
}

// LastNode is a free data retrieval call binding the contract method 0x200fc3ff.
//
// Solidity: function lastNode() view returns(address)
func (_Contract *ContractCaller) LastNode(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "lastNode")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// LastNode is a free data retrieval call binding the contract method 0x200fc3ff.
//
// Solidity: function lastNode() view returns(address)
func (_Contract *ContractSession) LastNode() (common.Address, error) {
	return _Contract.Contract.LastNode(&_Contract.CallOpts)
}

// LastNode is a free data retrieval call binding the contract method 0x200fc3ff.
//
// Solidity: function lastNode() view returns(address)
func (_Contract *ContractCallerSession) LastNode() (common.Address, error) {
	return _Contract.Contract.LastNode(&_Contract.CallOpts)
}

// LastOnlineNode is a free data retrieval call binding the contract method 0x04ad33bb.
//
// Solidity: function lastOnlineNode() view returns(address)
func (_Contract *ContractCaller) LastOnlineNode(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "lastOnlineNode")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// LastOnlineNode is a free data retrieval call binding the contract method 0x04ad33bb.
//
// Solidity: function lastOnlineNode() view returns(address)
func (_Contract *ContractSession) LastOnlineNode() (common.Address, error) {
	return _Contract.Contract.LastOnlineNode(&_Contract.CallOpts)
}

// LastOnlineNode is a free data retrieval call binding the contract method 0x04ad33bb.
//
// Solidity: function lastOnlineNode() view returns(address)
func (_Contract *ContractCallerSession) LastOnlineNode() (common.Address, error) {
	return _Contract.Contract.LastOnlineNode(&_Contract.CallOpts)
}

// NodeCost is a free data retrieval call binding the contract method 0x31deb7e1.
//
// Solidity: function nodeCost() view returns(uint256)
func (_Contract *ContractCaller) NodeCost(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "nodeCost")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// NodeCost is a free data retrieval call binding the contract method 0x31deb7e1.
//
// Solidity: function nodeCost() view returns(uint256)
func (_Contract *ContractSession) NodeCost() (*big.Int, error) {
	return _Contract.Contract.NodeCost(&_Contract.CallOpts)
}

// NodeCost is a free data retrieval call binding the contract method 0x31deb7e1.
//
// Solidity: function nodeCost() view returns(uint256)
func (_Contract *ContractCallerSession) NodeCost() (*big.Int, error) {
	return _Contract.Contract.NodeCost(&_Contract.CallOpts)
}

// Nodes is a free data retrieval call binding the contract method 0x189a5a17.
//
// Solidity: function nodes(address ) view returns(address preNode, address nextNode, address preOnlineNode, address nextOnlineNode, address investor, uint8 status, uint256 blockRegister, uint256 blockOnline, uint256 blockLastWithdraw, uint256 balancePledge, uint256 balancePledgeDebt, uint256 balanceMint, uint256 totalMint)
func (_Contract *ContractCaller) Nodes(opts *bind.CallOpts, arg0 common.Address) (struct {
	PreNode           common.Address
	NextNode          common.Address
	PreOnlineNode     common.Address
	NextOnlineNode    common.Address
	Investor          common.Address
	Status            uint8
	BlockRegister     *big.Int
	BlockOnline       *big.Int
	BlockLastWithdraw *big.Int
	BalancePledge     *big.Int
	BalancePledgeDebt *big.Int
	BalanceMint       *big.Int
	TotalMint         *big.Int
}, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "nodes", arg0)

	outstruct := new(struct {
		PreNode           common.Address
		NextNode          common.Address
		PreOnlineNode     common.Address
		NextOnlineNode    common.Address
		Investor          common.Address
		Status            uint8
		BlockRegister     *big.Int
		BlockOnline       *big.Int
		BlockLastWithdraw *big.Int
		BalancePledge     *big.Int
		BalancePledgeDebt *big.Int
		BalanceMint       *big.Int
		TotalMint         *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.PreNode = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.NextNode = *abi.ConvertType(out[1], new(common.Address)).(*common.Address)
	outstruct.PreOnlineNode = *abi.ConvertType(out[2], new(common.Address)).(*common.Address)
	outstruct.NextOnlineNode = *abi.ConvertType(out[3], new(common.Address)).(*common.Address)
	outstruct.Investor = *abi.ConvertType(out[4], new(common.Address)).(*common.Address)
	outstruct.Status = *abi.ConvertType(out[5], new(uint8)).(*uint8)
	outstruct.BlockRegister = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.BlockOnline = *abi.ConvertType(out[7], new(*big.Int)).(**big.Int)
	outstruct.BlockLastWithdraw = *abi.ConvertType(out[8], new(*big.Int)).(**big.Int)
	outstruct.BalancePledge = *abi.ConvertType(out[9], new(*big.Int)).(**big.Int)
	outstruct.BalancePledgeDebt = *abi.ConvertType(out[10], new(*big.Int)).(**big.Int)
	outstruct.BalanceMint = *abi.ConvertType(out[11], new(*big.Int)).(**big.Int)
	outstruct.TotalMint = *abi.ConvertType(out[12], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Nodes is a free data retrieval call binding the contract method 0x189a5a17.
//
// Solidity: function nodes(address ) view returns(address preNode, address nextNode, address preOnlineNode, address nextOnlineNode, address investor, uint8 status, uint256 blockRegister, uint256 blockOnline, uint256 blockLastWithdraw, uint256 balancePledge, uint256 balancePledgeDebt, uint256 balanceMint, uint256 totalMint)
func (_Contract *ContractSession) Nodes(arg0 common.Address) (struct {
	PreNode           common.Address
	NextNode          common.Address
	PreOnlineNode     common.Address
	NextOnlineNode    common.Address
	Investor          common.Address
	Status            uint8
	BlockRegister     *big.Int
	BlockOnline       *big.Int
	BlockLastWithdraw *big.Int
	BalancePledge     *big.Int
	BalancePledgeDebt *big.Int
	BalanceMint       *big.Int
	TotalMint         *big.Int
}, error) {
	return _Contract.Contract.Nodes(&_Contract.CallOpts, arg0)
}

// Nodes is a free data retrieval call binding the contract method 0x189a5a17.
//
// Solidity: function nodes(address ) view returns(address preNode, address nextNode, address preOnlineNode, address nextOnlineNode, address investor, uint8 status, uint256 blockRegister, uint256 blockOnline, uint256 blockLastWithdraw, uint256 balancePledge, uint256 balancePledgeDebt, uint256 balanceMint, uint256 totalMint)
func (_Contract *ContractCallerSession) Nodes(arg0 common.Address) (struct {
	PreNode           common.Address
	NextNode          common.Address
	PreOnlineNode     common.Address
	NextOnlineNode    common.Address
	Investor          common.Address
	Status            uint8
	BlockRegister     *big.Int
	BlockOnline       *big.Int
	BlockLastWithdraw *big.Int
	BalancePledge     *big.Int
	BalancePledgeDebt *big.Int
	BalanceMint       *big.Int
	TotalMint         *big.Int
}, error) {
	return _Contract.Contract.Nodes(&_Contract.CallOpts, arg0)
}

// PendingCalc is a free data retrieval call binding the contract method 0x69438d7b.
//
// Solidity: function pendingCalc(address nid) view returns(uint256)
func (_Contract *ContractCaller) PendingCalc(opts *bind.CallOpts, nid common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "pendingCalc", nid)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// PendingCalc is a free data retrieval call binding the contract method 0x69438d7b.
//
// Solidity: function pendingCalc(address nid) view returns(uint256)
func (_Contract *ContractSession) PendingCalc(nid common.Address) (*big.Int, error) {
	return _Contract.Contract.PendingCalc(&_Contract.CallOpts, nid)
}

// PendingCalc is a free data retrieval call binding the contract method 0x69438d7b.
//
// Solidity: function pendingCalc(address nid) view returns(uint256)
func (_Contract *ContractCallerSession) PendingCalc(nid common.Address) (*big.Int, error) {
	return _Contract.Contract.PendingCalc(&_Contract.CallOpts, nid)
}

// ReleaseBlocks is a free data retrieval call binding the contract method 0x70d1d031.
//
// Solidity: function releaseBlocks() view returns(uint256)
func (_Contract *ContractCaller) ReleaseBlocks(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "releaseBlocks")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// ReleaseBlocks is a free data retrieval call binding the contract method 0x70d1d031.
//
// Solidity: function releaseBlocks() view returns(uint256)
func (_Contract *ContractSession) ReleaseBlocks() (*big.Int, error) {
	return _Contract.Contract.ReleaseBlocks(&_Contract.CallOpts)
}

// ReleaseBlocks is a free data retrieval call binding the contract method 0x70d1d031.
//
// Solidity: function releaseBlocks() view returns(uint256)
func (_Contract *ContractCallerSession) ReleaseBlocks() (*big.Int, error) {
	return _Contract.Contract.ReleaseBlocks(&_Contract.CallOpts)
}

// Charge is a paid mutator transaction binding the contract method 0x55161913.
//
// Solidity: function charge() payable returns()
func (_Contract *ContractTransactor) Charge(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "charge")
}

// Charge is a paid mutator transaction binding the contract method 0x55161913.
//
// Solidity: function charge() payable returns()
func (_Contract *ContractSession) Charge() (*types.Transaction, error) {
	return _Contract.Contract.Charge(&_Contract.TransactOpts)
}

// Charge is a paid mutator transaction binding the contract method 0x55161913.
//
// Solidity: function charge() payable returns()
func (_Contract *ContractTransactorSession) Charge() (*types.Transaction, error) {
	return _Contract.Contract.Charge(&_Contract.TransactOpts)
}

// ForkContractData is a paid mutator transaction binding the contract method 0xc55ae72f.
//
// Solidity: function forkContractData(address src) returns()
func (_Contract *ContractTransactor) ForkContractData(opts *bind.TransactOpts, src common.Address) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "forkContractData", src)
}

// ForkContractData is a paid mutator transaction binding the contract method 0xc55ae72f.
//
// Solidity: function forkContractData(address src) returns()
func (_Contract *ContractSession) ForkContractData(src common.Address) (*types.Transaction, error) {
	return _Contract.Contract.ForkContractData(&_Contract.TransactOpts, src)
}

// ForkContractData is a paid mutator transaction binding the contract method 0xc55ae72f.
//
// Solidity: function forkContractData(address src) returns()
func (_Contract *ContractTransactorSession) ForkContractData(src common.Address) (*types.Transaction, error) {
	return _Contract.Contract.ForkContractData(&_Contract.TransactOpts, src)
}

// Logout is a paid mutator transaction binding the contract method 0x1f3c99c3.
//
// Solidity: function logout() returns()
func (_Contract *ContractTransactor) Logout(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "logout")
}

// Logout is a paid mutator transaction binding the contract method 0x1f3c99c3.
//
// Solidity: function logout() returns()
func (_Contract *ContractSession) Logout() (*types.Transaction, error) {
	return _Contract.Contract.Logout(&_Contract.TransactOpts)
}

// Logout is a paid mutator transaction binding the contract method 0x1f3c99c3.
//
// Solidity: function logout() returns()
func (_Contract *ContractTransactorSession) Logout() (*types.Transaction, error) {
	return _Contract.Contract.Logout(&_Contract.TransactOpts)
}

// Register is a paid mutator transaction binding the contract method 0x4420e486.
//
// Solidity: function register(address nid) payable returns()
func (_Contract *ContractTransactor) Register(opts *bind.TransactOpts, nid common.Address) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "register", nid)
}

// Register is a paid mutator transaction binding the contract method 0x4420e486.
//
// Solidity: function register(address nid) payable returns()
func (_Contract *ContractSession) Register(nid common.Address) (*types.Transaction, error) {
	return _Contract.Contract.Register(&_Contract.TransactOpts, nid)
}

// Register is a paid mutator transaction binding the contract method 0x4420e486.
//
// Solidity: function register(address nid) payable returns()
func (_Contract *ContractTransactorSession) Register(nid common.Address) (*types.Transaction, error) {
	return _Contract.Contract.Register(&_Contract.TransactOpts, nid)
}

// RegisterAgent is a paid mutator transaction binding the contract method 0x677321da.
//
// Solidity: function registerAgent(address nid, address owner) payable returns()
func (_Contract *ContractTransactor) RegisterAgent(opts *bind.TransactOpts, nid common.Address, owner common.Address) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "registerAgent", nid, owner)
}

// RegisterAgent is a paid mutator transaction binding the contract method 0x677321da.
//
// Solidity: function registerAgent(address nid, address owner) payable returns()
func (_Contract *ContractSession) RegisterAgent(nid common.Address, owner common.Address) (*types.Transaction, error) {
	return _Contract.Contract.RegisterAgent(&_Contract.TransactOpts, nid, owner)
}

// RegisterAgent is a paid mutator transaction binding the contract method 0x677321da.
//
// Solidity: function registerAgent(address nid, address owner) payable returns()
func (_Contract *ContractTransactorSession) RegisterAgent(nid common.Address, owner common.Address) (*types.Transaction, error) {
	return _Contract.Contract.RegisterAgent(&_Contract.TransactOpts, nid, owner)
}

// WithdrawMint is a paid mutator transaction binding the contract method 0xa8365f61.
//
// Solidity: function withdrawMint() returns()
func (_Contract *ContractTransactor) WithdrawMint(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "withdrawMint")
}

// WithdrawMint is a paid mutator transaction binding the contract method 0xa8365f61.
//
// Solidity: function withdrawMint() returns()
func (_Contract *ContractSession) WithdrawMint() (*types.Transaction, error) {
	return _Contract.Contract.WithdrawMint(&_Contract.TransactOpts)
}

// WithdrawMint is a paid mutator transaction binding the contract method 0xa8365f61.
//
// Solidity: function withdrawMint() returns()
func (_Contract *ContractTransactorSession) WithdrawMint() (*types.Transaction, error) {
	return _Contract.Contract.WithdrawMint(&_Contract.TransactOpts)
}

// WithdrawPledge is a paid mutator transaction binding the contract method 0x1209f7ed.
//
// Solidity: function withdrawPledge() returns()
func (_Contract *ContractTransactor) WithdrawPledge(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "withdrawPledge")
}

// WithdrawPledge is a paid mutator transaction binding the contract method 0x1209f7ed.
//
// Solidity: function withdrawPledge() returns()
func (_Contract *ContractSession) WithdrawPledge() (*types.Transaction, error) {
	return _Contract.Contract.WithdrawPledge(&_Contract.TransactOpts)
}

// WithdrawPledge is a paid mutator transaction binding the contract method 0x1209f7ed.
//
// Solidity: function withdrawPledge() returns()
func (_Contract *ContractTransactorSession) WithdrawPledge() (*types.Transaction, error) {
	return _Contract.Contract.WithdrawPledge(&_Contract.TransactOpts)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() returns()
func (_Contract *ContractTransactor) Fallback(opts *bind.TransactOpts, calldata []byte) (*types.Transaction, error) {
	return _Contract.contract.RawTransact(opts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() returns()
func (_Contract *ContractSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _Contract.Contract.Fallback(&_Contract.TransactOpts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() returns()
func (_Contract *ContractTransactorSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _Contract.Contract.Fallback(&_Contract.TransactOpts, calldata)
}

// ContractForkIterator is returned from FilterFork and is used to iterate over the raw logs and unpacked data for Fork events raised by the Contract contract.
type ContractForkIterator struct {
	Event *ContractFork // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContractForkIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContractFork)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContractFork)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContractForkIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContractForkIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContractFork represents a Fork event raised by the Contract contract.
type ContractFork struct {
	Src common.Address
	Dst common.Address
	Raw types.Log // Blockchain specific contextual infos
}

// FilterFork is a free log retrieval operation binding the contract event 0xcef34eae8f50e9e7369f1fe0973242562fc88687ca07b1e856397986cac6d3ad.
//
// Solidity: event fork(address src, address dst)
func (_Contract *ContractFilterer) FilterFork(opts *bind.FilterOpts) (*ContractForkIterator, error) {

	logs, sub, err := _Contract.contract.FilterLogs(opts, "fork")
	if err != nil {
		return nil, err
	}
	return &ContractForkIterator{contract: _Contract.contract, event: "fork", logs: logs, sub: sub}, nil
}

// WatchFork is a free log subscription operation binding the contract event 0xcef34eae8f50e9e7369f1fe0973242562fc88687ca07b1e856397986cac6d3ad.
//
// Solidity: event fork(address src, address dst)
func (_Contract *ContractFilterer) WatchFork(opts *bind.WatchOpts, sink chan<- *ContractFork) (event.Subscription, error) {

	logs, sub, err := _Contract.contract.WatchLogs(opts, "fork")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContractFork)
				if err := _Contract.contract.UnpackLog(event, "fork", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseFork is a log parse operation binding the contract event 0xcef34eae8f50e9e7369f1fe0973242562fc88687ca07b1e856397986cac6d3ad.
//
// Solidity: event fork(address src, address dst)
func (_Contract *ContractFilterer) ParseFork(log types.Log) (*ContractFork, error) {
	event := new(ContractFork)
	if err := _Contract.contract.UnpackLog(event, "fork", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ContractJoinIterator is returned from FilterJoin and is used to iterate over the raw logs and unpacked data for Join events raised by the Contract contract.
type ContractJoinIterator struct {
	Event *ContractJoin // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContractJoinIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContractJoin)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContractJoin)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContractJoinIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContractJoinIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContractJoin represents a Join event raised by the Contract contract.
type ContractJoin struct {
	Nid  common.Address
	Addr common.Address
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterJoin is a free log retrieval operation binding the contract event 0xb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e.
//
// Solidity: event join(address nid, address addr)
func (_Contract *ContractFilterer) FilterJoin(opts *bind.FilterOpts) (*ContractJoinIterator, error) {

	logs, sub, err := _Contract.contract.FilterLogs(opts, "join")
	if err != nil {
		return nil, err
	}
	return &ContractJoinIterator{contract: _Contract.contract, event: "join", logs: logs, sub: sub}, nil
}

// WatchJoin is a free log subscription operation binding the contract event 0xb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e.
//
// Solidity: event join(address nid, address addr)
func (_Contract *ContractFilterer) WatchJoin(opts *bind.WatchOpts, sink chan<- *ContractJoin) (event.Subscription, error) {

	logs, sub, err := _Contract.contract.WatchLogs(opts, "join")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContractJoin)
				if err := _Contract.contract.UnpackLog(event, "join", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseJoin is a log parse operation binding the contract event 0xb1c49079a0d59012846675cc20a8bbf8d52b2207a01bc968e01c89cb3571de5e.
//
// Solidity: event join(address nid, address addr)
func (_Contract *ContractFilterer) ParseJoin(log types.Log) (*ContractJoin, error) {
	event := new(ContractJoin)
	if err := _Contract.contract.UnpackLog(event, "join", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// ContractQuitIterator is returned from FilterQuit and is used to iterate over the raw logs and unpacked data for Quit events raised by the Contract contract.
type ContractQuitIterator struct {
	Event *ContractQuit // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ContractQuitIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ContractQuit)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ContractQuit)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ContractQuitIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ContractQuitIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ContractQuit represents a Quit event raised by the Contract contract.
type ContractQuit struct {
	Nid  common.Address
	Addr common.Address
	Raw  types.Log // Blockchain specific contextual infos
}

// FilterQuit is a free log retrieval operation binding the contract event 0x39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa165.
//
// Solidity: event quit(address nid, address addr)
func (_Contract *ContractFilterer) FilterQuit(opts *bind.FilterOpts) (*ContractQuitIterator, error) {

	logs, sub, err := _Contract.contract.FilterLogs(opts, "quit")
	if err != nil {
		return nil, err
	}
	return &ContractQuitIterator{contract: _Contract.contract, event: "quit", logs: logs, sub: sub}, nil
}

// WatchQuit is a free log subscription operation binding the contract event 0x39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa165.
//
// Solidity: event quit(address nid, address addr)
func (_Contract *ContractFilterer) WatchQuit(opts *bind.WatchOpts, sink chan<- *ContractQuit) (event.Subscription, error) {

	logs, sub, err := _Contract.contract.WatchLogs(opts, "quit")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ContractQuit)
				if err := _Contract.contract.UnpackLog(event, "quit", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseQuit is a log parse operation binding the contract event 0x39bcb31fc8c95224f57e8e4f443f9875a2d7c646c99cfa7ea4d4db7d6c2aa165.
//
// Solidity: event quit(address nid, address addr)
func (_Contract *ContractFilterer) ParseQuit(log types.Log) (*ContractQuit, error) {
	event := new(ContractQuit)
	if err := _Contract.contract.UnpackLog(event, "quit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
