// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.10;

contract Masternode {
    uint public constant nodeCost = 100 * 10**18;
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

    // -- Start -- 扩展功能： 质押期限与线性取回 --
    uint public constant blocksInDays180 = 60/3 * 5; //(3600*24/3) * 180;
    //enum pledgeOptions {Days0, Days180, Days360, Days540}
    struct nodeExt {
        //pledgeOptions pledgeDays;
        uint8 pledgeOptions; // Pledge Days: 0=0d, 1=180d, 2=360d, 3=540d
        uint pledgeBalance;
        uint blockOffline;
        uint blockFirstRetrieve;
        uint blockLastRetrieve;
    }
    mapping (address => nodeExt) public retrieveNodes;
    mapping (address => address[]) public retrieveNodesOf;
    event log_retrieve(address nid, address addr, uint amount, uint balance);
    // -- End --

    event join(address nid, address addr);
    event quit(address nid, address addr);

    //event log(string tips, uint8 data);
    event log(string tips, uint256 data);
    event log_uint(string tips, uint data);
    event log_uint8(string tips, uint8 data);
    event log_uint256(string tips, uint256 data);
    event log(string tips, bytes32 data);
    event log_bytes1(string tips, bytes1 data);
    event log(string tips, address data);
    event log_address(string tips, address data);
    event log_string(string tips, string data);

    // function register(address payable nid) public payable{
    //     register2(nid, msg.sender);
    // }

    function register(uint256 data) public payable{
        address payable nid = payable(address(uint160(data)));
        emit log_address("nid:", nid);
        //pledgeOptions pOpt = pledgeOptions(uint8(bytes21(uint168(data))[0]));
        uint8 pOpt = uint8(bytes21(uint168(data))[0]);
        emit log("pOpt:", pOpt);
        register2(nid, msg.sender, pOpt);
    }

    function register2(address payable nid, address owner, uint8 pledgeOptions) public payable{
        require(
            nid != address(0) &&
            address(0) == nodes[nid].investor &&
            msg.value == nodeCost &&
            (pledgeOptions == 0 || pledgeOptions == 1 || pledgeOptions == 2 || pledgeOptions == 3)
        );
        nodes[nid] = node(
            lastNode,address(0),
            address(0),address(0),
            owner,
            block.number,0,0,0
        );
        retrieveNodes[nid] = nodeExt(
            pledgeOptions, nodeCost, 0, 0, 0
        );
        if(lastNode != address(0)){
            nodes[lastNode].nextNode = nid;
        }
        lastNode = nid;
        nodesOf[owner].push(nid);
        countTotalNode += 1;
        nid.transfer(baseCost);
        retrieveNodes[nid].pledgeBalance -= baseCost;
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
                if(retrieveNodes[nid].pledgeOptions == 0){
                    //payable(msg.sender).transfer(nodeCost - baseCost);
                    payable(msg.sender).transfer(retrieveNodes[nid].pledgeBalance);
                    //retrieveNodes[nid].pledgeBalance = 0;
                    delete retrieveNodes[nid];
                } else {
                    retrieveNodesOf[msg.sender].push(nid);
                    retrieveNodes[nid].blockFirstRetrieve = block.number;
                    retrieveNodes[nid].blockLastRetrieve = block.number;
                }
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
            retrieveNodes[nid].blockOffline = block.number;
        }
    }

    function getInfo(address addr) public view returns (
        uint lockedBalance,
        uint totalNodes,
        uint onlineNodes,
        uint myNodes
    )
    {
        lockedBalance = address(this).balance / (10**18);
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

    function getInvestor(address nid) view public returns (address)
    {
        return nodes[nid].investor;
    }

    function getRetrieveNodes(address addr, uint startPos) public view
    returns (uint length, address[5] memory data) {
        address[] memory myIds = retrieveNodesOf[addr];
        length = uint(myIds.length);
        for(uint i = 0; i < 5 && (i+startPos) < length; i++) {
            data[i] = myIds[i+startPos];
        }
    }

    // get the last node's available retrieveBalance and the pledgeBalance
    function getPledgeBalance() public view returns (address, uint, uint) {
        //emit log_address("msg.sender=", msg.sender);
        uint index = retrieveNodesOf[msg.sender].length -1;
        //emit log_uint("index=", index);
        address nid = retrieveNodesOf[msg.sender][index];
        //emit log_address("nid=", nid);
        if (retrieveNodes[nid].pledgeOptions > 0) {
            //emit log_uint("block.number=", block.number);
            //emit log_uint("(block.number - retrieveNodes[nid].blockLastRetrieve)=", (block.number - retrieveNodes[nid].blockLastRetrieve));
            //emit log_uint("(retrieveNodes[nid].pledgeOptions * blocksInDays180)=", (retrieveNodes[nid].pledgeOptions * blocksInDays180));
            uint retrieveBalance =
            (block.number - retrieveNodes[nid].blockLastRetrieve) * retrieveNodes[nid].pledgeBalance
            / (retrieveNodes[nid].pledgeOptions * blocksInDays180);
            //emit log_uint("retrieveBalance=", retrieveBalance);
            if (retrieveBalance > retrieveNodes[nid].pledgeBalance) {
                retrieveBalance = retrieveNodes[nid].pledgeBalance;
            }
            return (nid, retrieveBalance, retrieveNodes[nid].pledgeBalance);
        } else {
            return (nid, 0, 0);
        }
    }

    // retrieve the available balance
    function retrieve() external payable {
        address nid;
        uint retrieveBalance;
        uint pledgeBalance;
        (nid, retrieveBalance, pledgeBalance) = getPledgeBalance();
        // uint index = retrieveNodesOf[msg.sender].length -1;
        // address nid = retrieveNodesOf[msg.sender][index];
        // if (retrieveNodes[nid].pledgeOptions > 0) {
        //     uint retrieveBalance =
        //         ((block.number - retrieveNodes[nid].blockLastRetrieve) / (retrieveNodes[nid].pledgeOptions * blocksInDays180))
        //         * retrieveNodes[nid].pledgeBalance;
        //     payable(msg.sender).transfer(retrieveBalance);
        //     retrieveNodes[nid].pledgeBalance -= retrieveBalance;
        //     if(retrieveNodes[nid].pledgeBalance <= 0) {
        //         delete retrieveNodes[nid];
        //         retrieveNodesOf[msg.sender].pop();
        //     }
        // }
        if (retrieveBalance > 0) {
            payable(msg.sender).transfer(retrieveBalance);
            emit log_retrieve(nid, msg.sender, retrieveBalance, retrieveNodes[nid].pledgeBalance);
            retrieveNodes[nid].pledgeBalance -= retrieveBalance;
            retrieveNodes[nid].blockLastRetrieve = block.number;
            if(retrieveNodes[nid].pledgeBalance <= 0) {
                delete retrieveNodes[nid];
                retrieveNodesOf[msg.sender].pop();
            }
        }
    }
}