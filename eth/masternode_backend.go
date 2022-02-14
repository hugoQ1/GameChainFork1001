package eth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/masternode/contract"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/types/masternode"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrUnknownMasternode = errors.New("unknown masternode")
)

type Masternode struct {
	index         int
	investor      common.Address
	status        uint8
	blockRegister uint64
	blockOnline   uint64
}

type MasternodeManager struct {
	eth             *Ethereum
	contractBackend *ContractBackend
	contract        *contract.Contract
	mux             *event.TypeMux
	rw              sync.RWMutex
	syncing         int32
	masternodeKeys  map[common.Address]*ecdsa.PrivateKey
	masternodes     map[common.Address]*Masternode
}

func NewMasternodeManager(eth *Ethereum) (*MasternodeManager, error) {
	contractBackend := NewContractBackend(eth)
	contract, err := contract.NewContract(params.MasternodeContractAddress, contractBackend)
	if err != nil {
		return nil, err
	}
	// Create the masternode manager with its initial settings
	manager := &MasternodeManager{
		eth:             eth,
		contractBackend: contractBackend,
		contract:        contract,
		masternodeKeys:  make(map[common.Address]*ecdsa.PrivateKey, params.MasternodeKeyCount),
		masternodes:     make(map[common.Address]*Masternode, params.MasternodeKeyCount),
		syncing:         0,
	}
	return manager, nil
}

func (self *MasternodeManager) Start(srvr *p2p.Server, mux *event.TypeMux) {
	self.mux = mux
	log.Info("Start masternode manqager!")
	for i, key := range srvr.Config.MasternodeKeys {
		id := crypto.PubkeyToAddress(key.PublicKey)
		account := self.newMasternode(i)
		self.masternodes[id] = account
		self.masternodeKeys[id] = key
		self.updateMasternodeFromContract(id)
	}
	go self.masternodeLoop()
	go self.checkSyncing()
}

func (self *MasternodeManager) SetMinerKey(index int, key *ecdsa.PrivateKey) (bool, common.Address) {
	addr := crypto.PubkeyToAddress(key.PublicKey)
	for id, account := range self.masternodes {
		if account.index == index {
			delete(self.masternodes, id)
			delete(self.masternodeKeys, id)
			if account.status == 1 {
				log.Warn("Active masternode be replaced!", "nid", id)
			}
			account := self.newMasternode(index)
			self.masternodes[addr] = account
			self.masternodeKeys[addr] = key
			self.updateMasternodeFromContract(addr)
			return true, id
		}
	}
	return false, common.Address{}
}

func (self *MasternodeManager) newMasternode(index int) *Masternode {
	return &Masternode{
		index: index,
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

	ping := time.NewTimer(60 * time.Second)
	defer ping.Stop()
	for {
		select {
		case err := <-joinSub.Err():
			joinSub.Unsubscribe()
			log.Error("Event Join", "error", err.Error())
		case err := <-quitSub.Err():
			quitSub.Unsubscribe()
			log.Error("Event Quit", "error", err.Error())
		case join := <-joinCh:
			if _, ok := self.masternodes[join.Nid]; ok {
				self.updateMasternodeFromContract(join.Nid)
			}
		case quit := <-quitCh:
			if _, ok := self.masternodes[quit.Nid]; ok {
				log.Warn("Remove masternode!", "nid", quit.Nid.String())
				self.updateMasternodeFromContract(quit.Nid)
			}
		case <-ping.C:
			ping.Reset(60 * time.Second)
			if atomic.LoadInt32(&self.syncing) == 1 {
				log.Warn("Syncing ...")
				break
			}
			if !self.eth.IsMining() {
				self.eth.StartMining(0)
				log.Warn("StartMining ...")
			}
			stateDB, _ := self.eth.blockchain.State()
			for nid, _ := range self.masternodes {
				self.updateMasternodeFromContract(nid)
				account := self.masternodes[nid]
				if account.status == 1 && account.blockOnline == 0 {
					ctx := context.Background()
					gasTipCap, err := self.eth.APIBackend.gpo.SuggestTipCap(ctx)
					if err != nil {
						log.Error("SuggestTipCap for transaction", "error", err.Error())
						continue
					}
					//msg := ethereum.CallMsg{
					//	From:      nid,
					//	To:        &params.MasternodeContractAddress,
					//	GasTipCap: gasTipCap,
					//	Data:      nil,
					//	Value:     big.NewInt(0),
					//}
					//EstimateGas, err := self.contractBackend.EstimateGas(ctx, msg)
					//if err != nil {
					//	fmt.Println("EstimateGas error:", err)
					//	//continue
					//}
					gasFeeCap := new(big.Int).Add(
						gasTipCap,
						new(big.Int).Mul(self.eth.blockchain.CurrentHeader().BaseFee, big.NewInt(2)),
					)
					gas := uint64(200000)
					fee := new(big.Int).Mul(big.NewInt(int64(gas)), gasFeeCap)
					if stateDB.GetBalance(nid).Cmp(fee) < 0 {
						log.Error("Insufficient balance for transaction.", nid.Hex(), "fee", fee, "balance", stateDB.GetBalance(nid).String())
						continue
					}
					baseTx := &types.DynamicFeeTx{
						To:        &params.MasternodeContractAddress,
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
						log.Error("Contract fallback", "error", err.Error())
						continue
					}
					if err := self.eth.txPool.AddLocal(signed); err != nil {
						log.Error("Add transaction to pool", "error", err.Error())
						continue
					}
					log.Warn("Send transaction for online", "nid", nid.String())
				}
			}
		}
	}
}

func (self *MasternodeManager) updateMasternodeFromContract(id common.Address) {
	node, err := self.contract.Nodes(nil, id)
	if err != nil {
		log.Error("Update masternode from contract", "error", err.Error())
		return
	}
	if node.Status > 0 {
		self.masternodes[id].investor = node.Investor
		self.masternodes[id].status = node.Status
		self.masternodes[id].blockRegister = node.BlockRegister.Uint64()
		self.masternodes[id].blockOnline = node.BlockOnline.Uint64()
	}
}
