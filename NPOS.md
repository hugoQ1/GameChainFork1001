# NPoS算法介绍

- 区块浏览器（内部测试）：[http://43.132.183.20:4000/](http://43.132.183.20:4000/)

## 1. 节点合约
- 合约地址：0x1111111111111111111111111111111111111111
- 合约代码：[contracts/masternode/contract/masternode.sol](https://github.com/rolong/mychain/blob/main/contracts/masternode/contract/masternode.sol)

- 节点合约是一个特殊的合约，在构建创世块（0区块）时进行初始化，并写入21个创世节点。
- 创世节点的初始质押币为0，创世节点的挖矿收益直接进入质押池，直至质押币数量达到最大值。

#### 1.1 属性说明

```
    address public lastNode; // 最近加入的节点ID
    address public lastOnlineNode; // 最近上线的节点ID
    uint public countTotalNode; // 节点总数（包含已经注销的节点）
    uint public countOnlineNode; // 在线节点总数
    uint public countReleasedNode; // 已经注销的节点（包含正在释放质押币的）
    uint public releaseBlocks; // 释放质押币的时间（区块数）
    uint public nodeCost; // 创建一个节点需要的质押币数量

    // 节点属性
    struct node {
        address preNode; // 上一个节点
        address nextNode; // 下一个节点
        address preOnlineNode; // 上一个在线节点
        address nextOnlineNode; // 下一个在线节点
        address investor; // 投资者（发送质押币创建节点的人）
        uint8 status; // 节点状态 (0=empty, 1=enable, 2=release)
        uint blockRegister; // 创建时间（区块号），创世节点的创建时间0
        uint blockOnline; // 最近上线时间（区块号）
        uint blockLastWithdraw; // 已注销的节点最近提取质押币的时间（区块号）
        uint balancePledge; // 质押币总量（如何是创世节点，质押币逐步增加，直到最大值nodeCost）
        uint balancePledgeDebt; // 已注销节点已经提走的质押币数量
        uint balanceMint; // 当前挖矿收益的可提取数量
    }

    mapping (address => node) public nodes; // 用节点ID查询节点属性
    mapping (address => address) public investor2nid; // 用投资者钱包查询对应节点ID
```

#### 1.2 方法说明

```
// 创建节点
function register(address payable nid) public payable

// 注销节点（注销后通过withdrawPledge方法提取质押币）
function logout() public

// 查询基本信息（在区块浏览器首页展示）
function getInfo() view public returns (
    uint totalBalance,
    uint totalNodes,
    uint onlineNodes,
    uint releaseNodes
)

// 查询当前挖矿收益 & 投资者已注销的节点质押币释放情况
function getReleaseInfo(address addr) view public returns (
    uint balanceMint,
    uint pendingAsset,
    uint lockedAsset,
    uint releaseTime
)

// 提取质押币（已经释放部分）
function withdrawPledge() public

// 提取挖矿收益
function withdrawMint() public
```

## 2. 节点列表
在节点合约里记录了2个双向链表：
- 一个包含所有节点的链表
- 一个只包含当前所有在线节点的链表

节点列表有4种类型：

#### 2.1 全部节点列表
包含了所有节点，包括已经注销的。
#### 2.2 有效节点列表
“全部节点列表”基础上，剔除已注销节点。
#### 2.3 在线节点列表
包含了所有在线节点。
#### 2.4 出块节点列表
允许当前出块的节点列表，包含了所有在线20分钟以上的节点。

## 3. 节点创建
后续开发节点管理页面，会有详细教程。
#### 3.1 运行节点
下载代码运行节点，等待数据同步完成后，获取节点ID为下一步做准备，节点ID是一个节点的唯一标识。

#### 3.2 发送质押币
打开节点管理页面，输入节点ID，发送质押币到节点合约。
质押币发送到节点合约，同时绑定了节点ID。
质押币不会存在节点服务器上，不会因为服务器被入侵导致资产损失。

#### 3.3 等待出块
节点会自动检测节点状态，发送质押币之后，变成有效节点，节点会自动上线，等待30分钟左右即可加入“出块节点列表”，自动启动挖矿。

## 4. 节点状态维护机制
#### 4.1 钱包节点 (node.status == 0)
节点刚运行时，为普通的钱包节点。

#### 4.2 有效节点 (node.status == 1)
节点检测到节点合约里有对应质押币的时候，转为有效节点。

#### 4.3 节点上线
节点检测到自己是离线状态，会自动发送一笔交易调用节点合约的上线方法。
上线20分钟后才能进入"出块列表"。

#### 4.4 节点离线
每个节点出块之前，会检测“出块列表”里的上一个节点是否有正常出块，
如果没有，立即设置为离线状态，从“在线列表”和“出块列表”中移除。
离线节点重新上线后，需等待20分钟作为惩罚，对于不能稳定出块的节点，收益会降低。

#### 4.5 节点失效 (node.status == 2)
节点对应的创建者发送交易调用节点合约的logout()方法之后，节点失效，从“有效列表“、“在线列表”和“出块列表”中移除，开始释放质押币。

## 5. 区块属性修改说明

#### 5.1 Block.Difficulty (big.Int)
在ETH里Difficulty字段是记录当前区块难度值的，现在修改为记录当前“出块列表”节点数量和当前出块的节点序号。

```
var length // “出块列表”节点数量
var index // 轮流出块的当前序号

Block.Difficulty = length * 1000000 + index

// 例如： 21,000,015
// 表示当前有21个节点参与出块，当前轮到了第15个节点出块
```

#### 5.1 Block.Nonce ([8]byte)
在ETH里Block.Nonce是用于PoW挖矿时记录随机数使用的，现在修改为记录下一个出块的节点ID和当前的“出块列表”哈希值，用于检测下一个节点是否正常出块。
```
var hash // “出块列表”哈希值（取开头的4字节）
var nodeId // 下一个出块的节点ID（取开头的4字节）

Block.Nonce = nodeId[0:4] + hash[0:4]

// 例如： 0xd89af0b30466d427
// 表示下一个出块节点ID的前4字节为：0xd89af0b3
// 当前“出块列表”哈希值的前4字节为：0x0466d427
```
