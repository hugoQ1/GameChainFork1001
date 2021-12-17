package masternode

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/masternode/contract"
	"math/big"
	"sort"
)

type MasternodeData struct {
	Index          int            `json:"index"     gencodec:"required"`
	Nid            common.Address `json:"nid"       gencodec:"required"`
	Data           string         `json:"data"      gencodec:"required"`
	Note           string         `json:"note"      gencodec:"required"`
	PrivateKey     string         `json:"privateKey"       gencodec:"required"`
	Investor       common.Address `json:"investor"`
	Status         uint64         `json:"status"`
	BlockRegister  uint64         `json:"blockRegister"`
	BlockLastPing  uint64         `json:"blockLastPing"`
	BlockOnline    uint64         `json:"blockOnline"`
	BlockOnlineAcc uint64         `json:"blockOnlineAcc"`
}

type MasternodeDatas []*MasternodeData

func (s MasternodeDatas) Len() int {
	return len(s)
}

func (s MasternodeDatas) Less(i, j int) bool {
	return s[i].Index < s[j].Index
}

func (s MasternodeDatas) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type Masternode struct {
	ID          common.Address
	Investor    common.Address
	OriginBlock *big.Int

	BlockOnline    *big.Int
	BlockOnlineAcc *big.Int
	BlockLastPing  *big.Int
}

func newMasternode(id, investor common.Address,
	block, blockOnline, blockOnlineAcc, blockLastPing *big.Int) *Masternode {
	return &Masternode{
		ID:             id,
		Investor:       investor,
		OriginBlock:    block,
		BlockOnline:    blockOnline,
		BlockOnlineAcc: blockOnlineAcc,
		BlockLastPing:  blockLastPing,
	}
}

func (n *Masternode) String() string {
	return fmt.Sprintf("Node: %x\n", n.ID.String())
}

func GetIdsByBlockNumber(contract *contract.Contract, blockNumber *big.Int) ([]common.Address, error) {
	if blockNumber == nil {
		blockNumber = new(big.Int)
	}

	ids, err := getOnlineIds(contract, blockNumber)
	if err == nil && len(ids) > 20 {
		sort.Sort(signersAscending(ids))
		return ids, nil
	}

	ids, err = getAllIds(contract, blockNumber)
	sort.Sort(signersAscending(ids))
	return ids, err
}

func getOnlineIds(contract *contract.Contract, blockNumber *big.Int) ([]common.Address, error) {
	opts := new(bind.CallOpts)
	opts.BlockNumber = blockNumber
	var (
		lastNode common.Address
		ctx      *MasternodeContext
		ids      []common.Address
	)
	lastNode, err := contract.LastOnlineNode(opts)
	if err != nil {
		return ids, err
	}
	for lastNode != (common.Address{}) {
		ctx, err = GetMasternodeContext(opts, contract, lastNode)
		if err != nil {
			fmt.Println("getOnlineIds1 error:", err)
			break
		}
		lastNode = ctx.preOnline
		// Offline after 21 minute
		if new(big.Int).Sub(blockNumber, ctx.Node.BlockLastPing).Cmp(big.NewInt(420)) > 0 {
			continue
		} else if ctx.Node.BlockOnline.Cmp(big.NewInt(400)) < 0 {
			continue
		}
		ids = append(ids, ctx.Node.ID)
	}
	if len(ids) > 20 {
		return ids, nil
	}
	lastNode, err = contract.LastOnlineNode(opts)
	if err != nil {
		return ids, err
	}
	for lastNode != (common.Address{}) {
		ctx, err = GetMasternodeContext(opts, contract, lastNode)
		if err != nil {
			fmt.Println("getOnlineIds2 error:", err)
			break
		}
		lastNode = ctx.preOnline
		if ctx.Node.BlockOnlineAcc.Cmp(big.NewInt(1)) < 0 {
			continue
		}
		ids = append(ids, ctx.Node.ID)
	}
	return ids, nil
}

func getAllIds(contract *contract.Contract, blockNumber *big.Int) ([]common.Address, error) {
	opts := new(bind.CallOpts)
	opts.BlockNumber = blockNumber
	var (
		lastNode common.Address
		ctx      *MasternodeContext
		ids      []common.Address
	)
	lastNode, err := contract.LastNode(opts)
	if err != nil {
		return ids, err
	}
	for lastNode != (common.Address{}) {
		ctx, err = GetMasternodeContext(opts, contract, lastNode)
		if err != nil {
			break
		}
		lastNode = ctx.pre
		ids = append(ids, ctx.Node.ID)
	}
	return ids, nil
}

type MasternodeContext struct {
	Node       *Masternode
	pre        common.Address
	next       common.Address
	preOnline  common.Address
	nextOnline common.Address
}

func GetMasternodeContext(opts *bind.CallOpts, contract *contract.Contract, id common.Address) (*MasternodeContext, error) {
	data, err := contract.ContractCaller.Nodes(opts, id)
	if err != nil {
		return &MasternodeContext{}, err
	}
	node := newMasternode(id, data.Investor, data.BlockRegister, data.BlockOnline, data.BlockOnlineAcc, data.BlockLastPing)

	return &MasternodeContext{
		Node:       node,
		pre:        data.PreNode,
		next:       data.NextNode,
		preOnline:  data.PreOnlineNode,
		nextOnline: data.NextOnlineNode,
	}, nil
}

// signersAscending implements the sort interface to allow sorting a list of addresses
type signersAscending []common.Address

func (s signersAscending) Len() int           { return len(s) }
func (s signersAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s signersAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

