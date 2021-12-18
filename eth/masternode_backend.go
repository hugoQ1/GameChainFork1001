package eth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/masternode/contract"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/types/masternode"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"log"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrUnknownMasternode = errors.New("unknown masternode")
)

type Masternode struct {
	index    int
	isActive bool

	investor       common.Address
	status         uint64
	blockRegister  uint64
	blockLastPing  uint64
	blockOnline    uint64
	blockOnlineAcc uint64
}

type MasternodeManager struct {
	// channels for fetcher, syncer, txsyncLoop
	IsMasternode uint32
	srvr         *p2p.Server
	contractBackend *ContractBackend
	contract     *contract.Contract

	mux *event.TypeMux
	eth *Ethereum

	syncing int32

	mu          sync.RWMutex
	rw          sync.RWMutex
	ID          string
	NodeAccount common.Address
	PrivateKey  *ecdsa.PrivateKey

	masternodeKeys map[common.Address]*ecdsa.PrivateKey
	masternodes    map[common.Address]*Masternode
}

func NewMasternodeManager(eth *Ethereum) (*MasternodeManager, error) {
	contractBackend := NewContractBackend(eth)
	contract1, err := contract.NewContract(params.MasterndeContractAddress, contractBackend)
	if err != nil {
		return nil, err
	}
	// Create the masternode manager with its initial settings
	manager := &MasternodeManager{
		eth:                eth,
		contractBackend: contractBackend,
		contract:           contract1,
		masternodeKeys:     make(map[common.Address]*ecdsa.PrivateKey, params.MasternodeKeyCount),
		masternodes: make(map[common.Address]*Masternode, params.MasternodeKeyCount),
		syncing:            0,
	}
	return manager, nil
}

func (self *MasternodeManager) Clear() {
	self.mu.Lock()
	defer self.mu.Unlock()

}

func (self *MasternodeManager) Start(srvr *p2p.Server, mux *event.TypeMux) {
	self.mux = mux
	log.Println("MasternodeManqager start ")
	for i, key := range srvr.Config.MasternodeKeys {
		id := crypto.PubkeyToAddress(key.PublicKey)
		account := self.newMasternode(i)
		self.masternodes[id] = account
		self.masternodeKeys[id] = key
		self.activeMasternode(id)
	}
	self.srvr = srvr
	go self.masternodeLoop()
	go self.checkSyncing()
}

func (self *MasternodeManager) SetMinerKey(index int, key *ecdsa.PrivateKey) (bool, common.Address) {
	addr := crypto.PubkeyToAddress(key.PublicKey)
	for id, account := range self.masternodes {
		if account.index == index {
			delete(self.masternodes, id)
			delete(self.masternodeKeys, id)

			if account.isActive {
				fmt.Println("Note: The active masternode(", id, ") was replaced!")
			}

			account := self.newMasternode(index)
			self.masternodes[addr] = account
			self.masternodeKeys[addr] = key
			self.activeMasternode(addr)
			return true, id
		}
	}
	return false, common.Address{}
}

func (self *MasternodeManager) newMasternode(index int) *Masternode {
	return &Masternode{
		index:   index,
	}
}

func (self *MasternodeManager) checkSyncing() {
	events := self.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
	for ev := range events.Chan() {
		switch ev.Data.(type) {
		case downloader.StartEvent:
			atomic.StoreInt32(&self.syncing, 1)
		case downloader.DoneEvent, downloader.FailedEvent:
			atomic.StoreInt32(&self.syncing, 0)
		}
	}
}

func (self *MasternodeManager) CheckMasternodeId(nid common.Address) bool {
	if _, ok := self.masternodeKeys[nid]; ok {
		return true
	}
	return false
}

func (self *MasternodeManager) MasternodeList(number *big.Int) ([]common.Address, error) {
	return masternode.GetIdsByBlockNumber(self.contract, number)
}

func (self *MasternodeManager) GetInvestor(nid common.Address, blockNumber *big.Int) (common.Address, error) {
	opts := new(bind.CallOpts)
	opts.BlockNumber = blockNumber
	node, err := self.contract.Nodes(opts, nid)
	if err != nil {
		return common.Address{}, err
	}
	return node.Investor, nil
}

func (self *MasternodeManager) SignHash(id common.Address, mimeType string, hash []byte) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	self.rw.RLock()
	defer self.rw.RUnlock()

	if key, ok := self.masternodeKeys[id]; ok {
		// Sign the hash using plain ECDSA operations
		return crypto.Sign(hash, key)
	}

	return nil, ErrUnknownMasternode
}

func (self *MasternodeManager) GetWitnesses() (ids []common.Address) {
	for id, _ := range self.masternodeKeys {
		ids = append(ids, id)
	}
	return ids
}

func (self *MasternodeManager) masternodeLoop() {
	joinCh := make(chan *contract.ContractJoin, 32)
	quitCh := make(chan *contract.ContractQuit, 32)
	joinSub, err1 := self.contract.WatchJoin(nil, joinCh)
	if err1 != nil {
		// TODO: exit
		return
	}
	quitSub, err2 := self.contract.WatchQuit(nil, quitCh)
	if err2 != nil {
		// TODO: exit
		return
	}

	ping := time.NewTimer(300 * time.Second)
	defer ping.Stop()
	for {
		select {
		case err := <-joinSub.Err():
			joinSub.Unsubscribe()
			fmt.Println("eventJoin err", err.Error())
		case err := <-quitSub.Err():
			quitSub.Unsubscribe()
			fmt.Println("eventQuit err", err.Error())
		case join := <-joinCh:
			if _, ok := self.masternodes[join.Nid]; ok {
				self.activeMasternode(join.Nid)
			}
		case quit := <-quitCh:
			if account, ok := self.masternodes[quit.Nid]; ok {
				fmt.Printf("### [%x] Remove masternode! \n", quit.Nid)
				account.isActive = false
			}
		case <-ping.C:
			logTime := time.Now().Format("[2006-01-02 15:04:05]")
			ping.Reset(20 * time.Second)
			if atomic.LoadInt32(&self.syncing) == 1 {
				fmt.Println(logTime, " syncing...")
				break
			}
			if !self.eth.IsMining() {
				self.eth.StartMining(0)
			}
			stateDB, _ := self.eth.blockchain.State()
			for nid, account := range self.masternodes {
				if account.isActive {
					ctx := context.Background()
					gasTipCap, err := self.eth.APIBackend.gpo.SuggestTipCap(ctx)
					if err != nil {
						fmt.Println("SuggestTipCap error:", err)
						continue
					}
					//msg := ethereum.CallMsg{
					//	From: nid,
					//	To: &params.MasterndeContractAddress,
					//	// GasTipCap: gasTipCap,
					//	Data: nil,
					//	Value: big.NewInt(0),
					//}
					//gas, err := self.contractBackend.EstimateGas(ctx, msg)
					//if err != nil {
					//	fmt.Println("EstimateGas error:", err)
					//	continue
					//}
					gasFeeCap := new(big.Int).Add(
						gasTipCap,
						new(big.Int).Mul(self.eth.blockchain.CurrentHeader().BaseFee, big.NewInt(2)),
					)
					gas := uint64(200000)
					fee := new(big.Int).Mul(big.NewInt(int64(gas)), gasFeeCap)
					fmt.Println("Gas:", gas, "gasTipCap:", gasTipCap.String(), "gasFeeCap:", gasFeeCap.String(), "fee:", fee.String())
					if stateDB.GetBalance(nid).Cmp(fee) < 0 {
						fmt.Println(logTime, "Insufficient balance for ping transaction.", nid.Hex(), self.eth.blockchain.CurrentBlock().Number().String(), stateDB.GetBalance(nid).String())
						continue
					}
					//opts := &bind.TransactOpts{
					//	From: nid,
					//	GasTipCap: gasTipCap,
					//	GasLimit: 200000,
					//	Value: big.NewInt(0),
					//	Signer: func(n common.Address, tx *types.Transaction) (*types.Transaction, error){
					//		fmt.Println("Signer", n.String(), tx.Nonce())
					//		return types.SignTx(tx, types.NewLondonSigner(self.eth.blockchain.Config().ChainID), self.masternodeKeys[n])
					//	},
					//}
					//signed, err := self.contract.Fallback(opts, nil)
					baseTx := &types.DynamicFeeTx{
						To:        &params.MasterndeContractAddress,
						Nonce:     self.eth.txPool.Nonce(nid),
						GasFeeCap: gasFeeCap,
						GasTipCap: gasTipCap,
						Gas:       gas,
						Value:     big.NewInt(0),
						Data:      nil,
					}
					tx := types.NewTx(baseTx)
					signed, err := types.SignTx(tx, types.NewLondonSigner(self.eth.blockchain.Config().ChainID), self.masternodeKeys[nid])
					if err != nil {
						fmt.Println(logTime, "Contract Fallback error:", err)
						continue
					}
					if err := self.eth.txPool.AddLocal(signed); err != nil {
						fmt.Println(logTime, "send ping to txpool error:", err)
						continue
					}
					fmt.Printf("%s [%s] Heartbeat\n", logTime, nid.String())
				} else {
					self.activeMasternode(nid)
				}
			}
		}
	}
}

func (self *MasternodeManager) activeMasternode(id common.Address) {
	node, err := self.contract.Nodes(nil, id)
	if err != nil {
		fmt.Println("[MN] activeMasternode Error:", err)
		return
	}

	if !self.masternodes[id].isActive && node.Investor != (common.Address{}) {
		self.masternodes[id].isActive = true
	}

	if node.Investor != (common.Address{}) {
		self.masternodes[id].investor = node.Investor
		self.masternodes[id].status = 1
		self.masternodes[id].blockRegister = node.BlockRegister.Uint64()
		self.masternodes[id].blockLastPing = node.BlockLastPing.Uint64()
		self.masternodes[id].blockOnline = node.BlockOnline.Uint64()
		self.masternodes[id].blockOnlineAcc = node.BlockOnlineAcc.Uint64()
	}
}
