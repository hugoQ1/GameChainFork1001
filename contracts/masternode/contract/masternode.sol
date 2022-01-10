// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.10;

contract Masternode {

    uint public constant baseCost = 10**18;

    address public lastNode; // 0
    address public lastOnlineNode; // 1
    uint public countTotalNode; // 2
    uint public countOnlineNode; // 3
    uint public countReleasedNode; // 4
    uint public releaseBlocks; // 5
    uint public nodeCost; // 6

    struct node {
        address preNode; // 0
        address nextNode; // 1
        address preOnlineNode; // 2
        address nextOnlineNode; // 3
        address investor; // 4
        uint8 status; // 4 (0=empty, 1=enable, 2=release)
        uint blockRegister; // 5
        uint blockOnline; // 6
        uint blockLastWithdraw; // 7
        uint balancePledge; // 8
        uint balancePledgeDebt; // 9
        uint balanceMint; // 10
    }

    mapping (address => node) public nodes; // 7
    mapping (address => address) public investor2nid; // 8

    event join(address nid, address addr);
    event quit(address nid, address addr);

    function register(address payable nid) public payable{
        registerAgent(nid, msg.sender);
    }

    function registerAgent(address payable nid, address owner) public payable{
        require(nid != address(0), "Invalid nid!");
        require(0 == nodes[nid].status, "The nid has been registered!");
        require(address(0) == investor2nid[owner], "The owner as been registered!");
        require(msg.value == nodeCost, "Invalid nodeCost!");
        nodes[nid] = node(
            lastNode,address(0),
            address(0),address(0),
            owner, 1,
            block.number,0,0,
            (nodeCost - baseCost), 0,
            0
        );
        if(lastNode != address(0)){
            nodes[lastNode].nextNode = nid;
        }
        lastNode = nid;
        investor2nid[owner] = nid;
        countTotalNode += 1;
        nid.transfer(baseCost);
        emit join(nid, owner);
    }

    function logout() public{
        address nid = investor2nid[msg.sender];
        require(1 == nodes[nid].status, "Has been released!");
        offline(nid);
        address preNode = nodes[nid].preNode;
        address nextNode = nodes[nid].nextNode;
        if(preNode != address(0)){
            nodes[preNode].nextNode = nextNode;
        }
        if(nextNode != address(0)){
            nodes[nextNode].preNode = preNode;
        }else{
            lastNode = preNode;
        }
        countReleasedNode += 1;
        nodes[nid].blockLastWithdraw = block.number;
        nodes[nid].status = 2;
        emit quit(nid, msg.sender);
    }

    function charge() public payable{
    }

    fallback() external {
        require(1 == nodes[msg.sender].status, "Invalid sender!");
        require(0 == nodes[msg.sender].blockOnline, "Already online!");
        nodes[msg.sender].blockOnline = block.number;
        countOnlineNode += 1;
        if(lastOnlineNode != address(0)){
            nodes[lastOnlineNode].nextOnlineNode = msg.sender;
        }
        nodes[msg.sender].preOnlineNode = lastOnlineNode;
        nodes[msg.sender].nextOnlineNode = address(0);
        lastOnlineNode = msg.sender;
    }

    function offline(address nid) internal {
        if (nodes[nid].blockOnline > 0){
            countOnlineNode -= 1;
            nodes[nid].blockOnline = 0;
            address preOnlineNode = nodes[nid].preOnlineNode;
            address nextOnlineNode = nodes[nid].nextOnlineNode;
            if(preOnlineNode != address(0)){
                nodes[preOnlineNode].nextOnlineNode = nextOnlineNode;
                nodes[nid].preOnlineNode = address(0);
            }
            if(nextOnlineNode != address(0)){
                nodes[nextOnlineNode].preOnlineNode = preOnlineNode;
                nodes[nid].nextOnlineNode = address(0);
            }else{
                lastOnlineNode = preOnlineNode;
            }
        }
    }

    function getInfo() view public returns (
        uint totalBalance,
        uint totalNodes,
        uint onlineNodes,
        uint releaseNodes
    )
    {
        totalBalance = address(this).balance / (10**18);
        totalNodes = countTotalNode;
        onlineNodes = countOnlineNode;
        releaseNodes = countReleasedNode;
    }

    function getReleaseInfo(address addr) view public returns (
        uint balanceMint,
        uint pendingAsset,
        uint lockedAsset,
        uint releaseTime
    )
    {
        address nid = investor2nid[addr];
        balanceMint = nodes[nid].balanceMint;
        if(nodes[nid].status == 2){
            pendingAsset = pendingCalc(nid);
            lockedAsset = nodes[nid].balancePledge - nodes[nid].balancePledgeDebt - pendingAsset;
            uint releasePerBlock = nodes[nid].balancePledge / releaseBlocks;
            releaseTime = lockedAsset / releasePerBlock * 3;
        }
    }

    function has(address nid) view public returns (bool)
    {
        return nodes[nid].status == 1;
    }

    function getInvestor(address nid) view public returns (address)
    {
        return nodes[nid].investor;
    }

    function pendingCalc(address nid) view public returns (uint){
        if (nodes[nid].status != 2) return 0;
        uint gapBlocks = block.number - nodes[nid].blockLastWithdraw;
        uint releasePerBlock = nodes[nid].balancePledge / releaseBlocks;
        uint pendingAsset = gapBlocks * releasePerBlock;
        uint pendingAssetMax = nodes[nid].balancePledge - nodes[nid].balancePledgeDebt;
        if(pendingAsset > pendingAssetMax){
            pendingAsset = pendingAssetMax;
        }
        return pendingAsset;
    }

    function withdrawPledge() public{
        address nid = investor2nid[msg.sender];
        require(nid != address(0), "Don't have node");
        require(nodes[nid].blockLastWithdraw > 0 && nodes[nid].status == 2, "Not yet released");
        require(block.number > nodes[nid].blockLastWithdraw, "Invalid blockLastWithdraw");
        uint pendingAsset = pendingCalc(nid);
        nodes[nid].balancePledgeDebt += pendingAsset;
        nodes[nid].blockLastWithdraw = block.number;
        payable(msg.sender).transfer(pendingAsset);
    }

    function withdrawMint() public{
        address nid = investor2nid[msg.sender];
        require(nid != address(0), "Don't have node");
        uint balanceMint = nodes[nid].balanceMint;
        nodes[nid].balanceMint = 0;
        payable(msg.sender).transfer(balanceMint);
    }

}