// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.10;

contract Masternode {

    uint public constant nodeCost = 10000 * 10**18;
    uint public constant baseCost = 10**18;
    uint public constant minBlockTimeout = 800;

    address public lastNode;
    address public lastOnlineNode;
    uint public countTotalNode;
    uint public countOnlineNode;

    struct node {
        address preNode;
        address nextNode;
        address preOnlineNode;
        address nextOnlineNode;
        address investor;
        uint blockRegister;
        uint blockLastPing;
        uint blockOnline;
        uint blockOnlineAcc;
    }

    mapping (address => node) public nodes;
    mapping (address => address[]) public nodesOf;

    event join(address nid, address addr);
    event quit(address nid, address addr);

    function register(address payable nid) public payable{
        register2(nid, msg.sender);
    }

    function register2(address payable nid, address owner) public payable{
        require(
            nid != address(0) &&
            address(0) == nodes[nid].investor &&
            msg.value == nodeCost
        );
        nodes[nid] = node(
            lastNode,address(0),
            address(0),address(0),
            owner,
            block.number,0,0,0
        );
        if(lastNode != address(0)){
            nodes[lastNode].nextNode = nid;
        }
        lastNode = nid;
        nodesOf[owner].push(nid);
        countTotalNode += 1;
        nid.transfer(baseCost);
        emit join(nid, owner);
    }

    receive() external payable {
        if (address(0) != nodes[msg.sender].investor){
            // ping
            if(0 == nodes[msg.sender].blockOnline){
                nodes[msg.sender].blockOnline = 1;
                countOnlineNode += 1;
                if(lastOnlineNode != address(0)){
                    nodes[lastOnlineNode].nextOnlineNode = msg.sender;
                }
                nodes[msg.sender].preOnlineNode = lastOnlineNode;
                nodes[msg.sender].nextOnlineNode = address(0);
                lastOnlineNode = msg.sender;
            }else if(nodes[msg.sender].blockLastPing > 0){
                uint blockGap = block.number - nodes[msg.sender].blockLastPing;
                if(blockGap > minBlockTimeout){
                    nodes[msg.sender].blockOnline = 1;
                }else{
                    nodes[msg.sender].blockOnline += blockGap;
                    nodes[msg.sender].blockOnlineAcc += blockGap;
                }
            }
            nodes[msg.sender].blockLastPing = block.number;
            fix(nodes[msg.sender].preOnlineNode);
            fix(nodes[msg.sender].nextOnlineNode);
        }else if(nodesOf[msg.sender].length > 0){
            uint index = nodesOf[msg.sender].length -1;
            address nid = nodesOf[msg.sender][index];
            require(address(0) != nodes[nid].investor);
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
            bool notGenesisNode = nodes[nid].blockRegister > 0;
            delete nodes[nid];
            nodesOf[msg.sender].pop();
            countTotalNode -= 1;
            emit quit(nid, msg.sender);
            if(notGenesisNode){
                payable(msg.sender).transfer(nodeCost - baseCost);
            }
        }
    }

    function fix(address nid) internal {
        if (address(0) != nodes[nid].investor){
            if((block.number - nodes[nid].blockLastPing) > minBlockTimeout){
                offline(nid);
            }
        }
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

    function getInfo(address addr) view public returns (
        uint lockedBalance,
        uint releasedReward,
        uint totalNodes,
        uint onlineNodes,
        uint myNodes
    )
    {
        lockedBalance = address(this).balance / (10**18);
        releasedReward = block.number * 48 / 10;
        totalNodes = countTotalNode;
        onlineNodes = countOnlineNode;
        myNodes = nodesOf[addr].length;
    }

    function getNodes(address addr, uint startPos) public view
    returns (uint length, address[5] memory data) {
        address[] memory myIds = nodesOf[addr];
        length = uint(myIds.length);
        for(uint i = 0; i < 5 && (i+startPos) < length; i++) {
            data[i] = myIds[i+startPos];
        }
    }

    function has(address nid) view public returns (bool)
    {
        return nodes[nid].investor != address(0);
    }

    function getInvestor(address nid) view public returns (bool)
    {
        return nodes[nid].investor != address(0);
    }
}