// SPDX-License-Identifier: MIT

pragma solidity 0.8.11;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract Investment {
    address private implementation;
    address private owner;
    address[] public donaters;

    using SafeMath for uint;

    mapping (address => bool) private _minted;
    mapping (bytes32 => uint) private _total_stocks;
    mapping (bytes32 => uint) private _reg_stocks;
    mapping (address => mapping (bytes32 => uint)) private _stocks;
    mapping (address => uint) private _balances;

    address lastDonater;
    uint fee;
    uint denominator;
    bool inited;

    event solved(address);

    modifier isInited {
        require(inited);
        _;
    }

    constructor(address target) {
        IInvestment friend = IInvestment(target);
        friend.mint();
        friend.buyStock("apple", 1);
        friend.donateStock(address(this), "apple", 1);
    }

    // Patched
    function isSolved() public isInited {
        emit solved(msg.sender);
        address payable addr = payable(address(0));
        selfdestruct(addr);
    }
}

interface IInvestment {
    function mint() external;
    function buyStock(string memory _stockName, uint _amountOfStock) external;
    function donateStock(address _to, string memory _stockName, uint _amountOfStock) external;
}
