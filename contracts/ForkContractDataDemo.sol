// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.10;

interface Masternode {
    function  forkContractData(address from)  external;
}

contract NewContract {

    // 原合约的属性不能删除、不能调整属性顺序，，可以在末尾增加
    // 结构体里面的元素，不能删除、不能调整属性顺序，可以在末尾增加
    // function 不受限制，可以自由调整
    // 因为是用Fork老合约来初始化数据的，所以新合约不能有构造函数

    // 新合约必须添加此方法，新合约部署完毕后，调用此方法即可Fork老合约的数据
    function fork() public {
        address oldContract = "你需要Fork的目标合约地址"
        Masternode(0x1111111111111111111111111111111111111111).forkContractData(oldContract);
    }

}