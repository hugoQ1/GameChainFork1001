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
	ABI: "[{\"constant\":true,\"inputs\":[],\"name\":\"countOnlineNode\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"lastOnlineNode\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"nodes\",\"outputs\":[{\"name\":\"preNode\",\"type\":\"address\"},{\"name\":\"nextNode\",\"type\":\"address\"},{\"name\":\"preOnlineNode\",\"type\":\"address\"},{\"name\":\"nextOnlineNode\",\"type\":\"address\"},{\"name\":\"investor\",\"type\":\"address\"},{\"name\":\"blockRegister\",\"type\":\"uint256\"},{\"name\":\"blockLastPing\",\"type\":\"uint256\"},{\"name\":\"blockOnline\",\"type\":\"uint256\"},{\"name\":\"blockOnlineAcc\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"lastNode\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"nid\",\"type\":\"address\"}],\"name\":\"has\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"nodeCost\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"nodesOf\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"nid\",\"type\":\"address\"}],\"name\":\"register\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"countTotalNode\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"nid\",\"type\":\"address\"}],\"name\":\"getInvestor\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"baseCost\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"nid\",\"type\":\"address\"},{\"name\":\"owner\",\"type\":\"address\"}],\"name\":\"register2\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"minBlockTimeout\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"},{\"name\":\"startPos\",\"type\":\"uint256\"}],\"name\":\"getNodes\",\"outputs\":[{\"name\":\"length\",\"type\":\"uint256\"},{\"name\":\"data\",\"type\":\"address[5]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"getInfo\",\"outputs\":[{\"name\":\"lockedBalance\",\"type\":\"uint256\"},{\"name\":\"releasedReward\",\"type\":\"uint256\"},{\"name\":\"totalNodes\",\"type\":\"uint256\"},{\"name\":\"onlineNodes\",\"type\":\"uint256\"},{\"name\":\"myNodes\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"fallback\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"nid\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"join\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"name\":\"nid\",\"type\":\"address\"},{\"indexed\":false,\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"quit\",\"type\":\"event\"}]",
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

// GetInfo is a free data retrieval call binding the contract method 0xffdd5cf1.
//
// Solidity: function getInfo(address addr) view returns(uint256 lockedBalance, uint256 releasedReward, uint256 totalNodes, uint256 onlineNodes, uint256 myNodes)
func (_Contract *ContractCaller) GetInfo(opts *bind.CallOpts, addr common.Address) (struct {
	LockedBalance  *big.Int
	ReleasedReward *big.Int
	TotalNodes     *big.Int
	OnlineNodes    *big.Int
	MyNodes        *big.Int
}, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getInfo", addr)

	outstruct := new(struct {
		LockedBalance  *big.Int
		ReleasedReward *big.Int
		TotalNodes     *big.Int
		OnlineNodes    *big.Int
		MyNodes        *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.LockedBalance = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.ReleasedReward = *abi.ConvertType(out[1], new(*big.Int)).(**big.Int)
	outstruct.TotalNodes = *abi.ConvertType(out[2], new(*big.Int)).(**big.Int)
	outstruct.OnlineNodes = *abi.ConvertType(out[3], new(*big.Int)).(**big.Int)
	outstruct.MyNodes = *abi.ConvertType(out[4], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// GetInfo is a free data retrieval call binding the contract method 0xffdd5cf1.
//
// Solidity: function getInfo(address addr) view returns(uint256 lockedBalance, uint256 releasedReward, uint256 totalNodes, uint256 onlineNodes, uint256 myNodes)
func (_Contract *ContractSession) GetInfo(addr common.Address) (struct {
	LockedBalance  *big.Int
	ReleasedReward *big.Int
	TotalNodes     *big.Int
	OnlineNodes    *big.Int
	MyNodes        *big.Int
}, error) {
	return _Contract.Contract.GetInfo(&_Contract.CallOpts, addr)
}

// GetInfo is a free data retrieval call binding the contract method 0xffdd5cf1.
//
// Solidity: function getInfo(address addr) view returns(uint256 lockedBalance, uint256 releasedReward, uint256 totalNodes, uint256 onlineNodes, uint256 myNodes)
func (_Contract *ContractCallerSession) GetInfo(addr common.Address) (struct {
	LockedBalance  *big.Int
	ReleasedReward *big.Int
	TotalNodes     *big.Int
	OnlineNodes    *big.Int
	MyNodes        *big.Int
}, error) {
	return _Contract.Contract.GetInfo(&_Contract.CallOpts, addr)
}

// GetInvestor is a free data retrieval call binding the contract method 0x8f35a75e.
//
// Solidity: function getInvestor(address nid) view returns(bool)
func (_Contract *ContractCaller) GetInvestor(opts *bind.CallOpts, nid common.Address) (bool, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getInvestor", nid)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetInvestor is a free data retrieval call binding the contract method 0x8f35a75e.
//
// Solidity: function getInvestor(address nid) view returns(bool)
func (_Contract *ContractSession) GetInvestor(nid common.Address) (bool, error) {
	return _Contract.Contract.GetInvestor(&_Contract.CallOpts, nid)
}

// GetInvestor is a free data retrieval call binding the contract method 0x8f35a75e.
//
// Solidity: function getInvestor(address nid) view returns(bool)
func (_Contract *ContractCallerSession) GetInvestor(nid common.Address) (bool, error) {
	return _Contract.Contract.GetInvestor(&_Contract.CallOpts, nid)
}

// GetNodes is a free data retrieval call binding the contract method 0xf90638a3.
//
// Solidity: function getNodes(address addr, uint256 startPos) view returns(uint256 length, address[5] data)
func (_Contract *ContractCaller) GetNodes(opts *bind.CallOpts, addr common.Address, startPos *big.Int) (struct {
	Length *big.Int
	Data   [5]common.Address
}, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "getNodes", addr, startPos)

	outstruct := new(struct {
		Length *big.Int
		Data   [5]common.Address
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Length = *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)
	outstruct.Data = *abi.ConvertType(out[1], new([5]common.Address)).(*[5]common.Address)

	return *outstruct, err

}

// GetNodes is a free data retrieval call binding the contract method 0xf90638a3.
//
// Solidity: function getNodes(address addr, uint256 startPos) view returns(uint256 length, address[5] data)
func (_Contract *ContractSession) GetNodes(addr common.Address, startPos *big.Int) (struct {
	Length *big.Int
	Data   [5]common.Address
}, error) {
	return _Contract.Contract.GetNodes(&_Contract.CallOpts, addr, startPos)
}

// GetNodes is a free data retrieval call binding the contract method 0xf90638a3.
//
// Solidity: function getNodes(address addr, uint256 startPos) view returns(uint256 length, address[5] data)
func (_Contract *ContractCallerSession) GetNodes(addr common.Address, startPos *big.Int) (struct {
	Length *big.Int
	Data   [5]common.Address
}, error) {
	return _Contract.Contract.GetNodes(&_Contract.CallOpts, addr, startPos)
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

// MinBlockTimeout is a free data retrieval call binding the contract method 0xa737b186.
//
// Solidity: function minBlockTimeout() view returns(uint256)
func (_Contract *ContractCaller) MinBlockTimeout(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "minBlockTimeout")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// MinBlockTimeout is a free data retrieval call binding the contract method 0xa737b186.
//
// Solidity: function minBlockTimeout() view returns(uint256)
func (_Contract *ContractSession) MinBlockTimeout() (*big.Int, error) {
	return _Contract.Contract.MinBlockTimeout(&_Contract.CallOpts)
}

// MinBlockTimeout is a free data retrieval call binding the contract method 0xa737b186.
//
// Solidity: function minBlockTimeout() view returns(uint256)
func (_Contract *ContractCallerSession) MinBlockTimeout() (*big.Int, error) {
	return _Contract.Contract.MinBlockTimeout(&_Contract.CallOpts)
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
// Solidity: function nodes(address ) view returns(address preNode, address nextNode, address preOnlineNode, address nextOnlineNode, address investor, uint256 blockRegister, uint256 blockLastPing, uint256 blockOnline, uint256 blockOnlineAcc)
func (_Contract *ContractCaller) Nodes(opts *bind.CallOpts, arg0 common.Address) (struct {
	PreNode        common.Address
	NextNode       common.Address
	PreOnlineNode  common.Address
	NextOnlineNode common.Address
	Investor       common.Address
	BlockRegister  *big.Int
	BlockLastPing  *big.Int
	BlockOnline    *big.Int
	BlockOnlineAcc *big.Int
}, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "nodes", arg0)

	outstruct := new(struct {
		PreNode        common.Address
		NextNode       common.Address
		PreOnlineNode  common.Address
		NextOnlineNode common.Address
		Investor       common.Address
		BlockRegister  *big.Int
		BlockLastPing  *big.Int
		BlockOnline    *big.Int
		BlockOnlineAcc *big.Int
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.PreNode = *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	outstruct.NextNode = *abi.ConvertType(out[1], new(common.Address)).(*common.Address)
	outstruct.PreOnlineNode = *abi.ConvertType(out[2], new(common.Address)).(*common.Address)
	outstruct.NextOnlineNode = *abi.ConvertType(out[3], new(common.Address)).(*common.Address)
	outstruct.Investor = *abi.ConvertType(out[4], new(common.Address)).(*common.Address)
	outstruct.BlockRegister = *abi.ConvertType(out[5], new(*big.Int)).(**big.Int)
	outstruct.BlockLastPing = *abi.ConvertType(out[6], new(*big.Int)).(**big.Int)
	outstruct.BlockOnline = *abi.ConvertType(out[7], new(*big.Int)).(**big.Int)
	outstruct.BlockOnlineAcc = *abi.ConvertType(out[8], new(*big.Int)).(**big.Int)

	return *outstruct, err

}

// Nodes is a free data retrieval call binding the contract method 0x189a5a17.
//
// Solidity: function nodes(address ) view returns(address preNode, address nextNode, address preOnlineNode, address nextOnlineNode, address investor, uint256 blockRegister, uint256 blockLastPing, uint256 blockOnline, uint256 blockOnlineAcc)
func (_Contract *ContractSession) Nodes(arg0 common.Address) (struct {
	PreNode        common.Address
	NextNode       common.Address
	PreOnlineNode  common.Address
	NextOnlineNode common.Address
	Investor       common.Address
	BlockRegister  *big.Int
	BlockLastPing  *big.Int
	BlockOnline    *big.Int
	BlockOnlineAcc *big.Int
}, error) {
	return _Contract.Contract.Nodes(&_Contract.CallOpts, arg0)
}

// Nodes is a free data retrieval call binding the contract method 0x189a5a17.
//
// Solidity: function nodes(address ) view returns(address preNode, address nextNode, address preOnlineNode, address nextOnlineNode, address investor, uint256 blockRegister, uint256 blockLastPing, uint256 blockOnline, uint256 blockOnlineAcc)
func (_Contract *ContractCallerSession) Nodes(arg0 common.Address) (struct {
	PreNode        common.Address
	NextNode       common.Address
	PreOnlineNode  common.Address
	NextOnlineNode common.Address
	Investor       common.Address
	BlockRegister  *big.Int
	BlockLastPing  *big.Int
	BlockOnline    *big.Int
	BlockOnlineAcc *big.Int
}, error) {
	return _Contract.Contract.Nodes(&_Contract.CallOpts, arg0)
}

// NodesOf is a free data retrieval call binding the contract method 0x367d5e62.
//
// Solidity: function nodesOf(address , uint256 ) view returns(address)
func (_Contract *ContractCaller) NodesOf(opts *bind.CallOpts, arg0 common.Address, arg1 *big.Int) (common.Address, error) {
	var out []interface{}
	err := _Contract.contract.Call(opts, &out, "nodesOf", arg0, arg1)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// NodesOf is a free data retrieval call binding the contract method 0x367d5e62.
//
// Solidity: function nodesOf(address , uint256 ) view returns(address)
func (_Contract *ContractSession) NodesOf(arg0 common.Address, arg1 *big.Int) (common.Address, error) {
	return _Contract.Contract.NodesOf(&_Contract.CallOpts, arg0, arg1)
}

// NodesOf is a free data retrieval call binding the contract method 0x367d5e62.
//
// Solidity: function nodesOf(address , uint256 ) view returns(address)
func (_Contract *ContractCallerSession) NodesOf(arg0 common.Address, arg1 *big.Int) (common.Address, error) {
	return _Contract.Contract.NodesOf(&_Contract.CallOpts, arg0, arg1)
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

// Register2 is a paid mutator transaction binding the contract method 0x960d59f8.
//
// Solidity: function register2(address nid, address owner) payable returns()
func (_Contract *ContractTransactor) Register2(opts *bind.TransactOpts, nid common.Address, owner common.Address) (*types.Transaction, error) {
	return _Contract.contract.Transact(opts, "register2", nid, owner)
}

// Register2 is a paid mutator transaction binding the contract method 0x960d59f8.
//
// Solidity: function register2(address nid, address owner) payable returns()
func (_Contract *ContractSession) Register2(nid common.Address, owner common.Address) (*types.Transaction, error) {
	return _Contract.Contract.Register2(&_Contract.TransactOpts, nid, owner)
}

// Register2 is a paid mutator transaction binding the contract method 0x960d59f8.
//
// Solidity: function register2(address nid, address owner) payable returns()
func (_Contract *ContractTransactorSession) Register2(nid common.Address, owner common.Address) (*types.Transaction, error) {
	return _Contract.Contract.Register2(&_Contract.TransactOpts, nid, owner)
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
