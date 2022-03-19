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

    function init() public {
        require(!inited);

        _reg_stocks[keccak256("apple")] = 111;
        _total_stocks[keccak256("apple")] = 99999999;
        _reg_stocks[keccak256("microsoft")] = 101;
        _total_stocks[keccak256("microsoft")] = 99999999;
        _reg_stocks[keccak256("intel")] = 97;
        _total_stocks[keccak256("intel")] = 99999999;
        _reg_stocks[keccak256("amd")] = 74;
        _total_stocks[keccak256("amd")] = 99999999;
        _reg_stocks[keccak256("codegate")] = 11111111111111111111111111111111111111;
        _total_stocks[keccak256("codegate")] = 1;
        fee = 5;
        denominator = 1e4;
        inited = true;
    }

    function buyStock(string memory _stockName, uint _amountOfStock) public isInited {
        bytes32 stockName = keccak256(abi.encodePacked(_stockName));
        require(_total_stocks[stockName] > 0 && _amountOfStock > 0);
        uint amount = _reg_stocks[stockName].mul(_amountOfStock).mul(denominator + fee).div(denominator);
        require(_balances[msg.sender] >= amount);

        _balances[msg.sender] -= amount;
        _stocks[msg.sender][stockName] += _amountOfStock;
        _total_stocks[stockName] -= _amountOfStock;
    }

    function sellStock(string memory _stockName, uint _amountOfStock) public isInited {
        bytes32 stockName = keccak256(abi.encodePacked(_stockName));
        require(_amountOfStock > 0);
        uint amount = _reg_stocks[stockName].mul(_amountOfStock).mul(denominator).div(denominator + fee);
        require(_stocks[msg.sender][stockName] >= _amountOfStock);
        _balances[msg.sender] += amount;
        _stocks[msg.sender][stockName] -= _amountOfStock;
        _total_stocks[stockName] += _amountOfStock;
    }

    function donateStock(address _to, string memory _stockName, uint _amountOfStock) public isInited {
        bytes32 stockName = keccak256(abi.encodePacked(_stockName));
        require(_amountOfStock > 0);
        require(isUser(msg.sender) && _stocks[msg.sender][stockName] >= _amountOfStock);
        _stocks[msg.sender][stockName] -= _amountOfStock;
        (bool success, bytes memory result) = msg.sender.call(abi.encodeWithSignature("receiveStock(address,bytes32,uint256)", _to, stockName, _amountOfStock));
        require(success);
        lastDonater = msg.sender;
        donaters.push(lastDonater);
    }

    function isInvalidDonaters(uint index) internal returns (bool) {
        require(donaters.length > index);
        if (!isUser(lastDonater)) {
            return true;
        }
        else {
            return false;
        }
    }

    function modifyDonater(uint index) public isInited {
        require(isInvalidDonaters(index));
        donaters[index] = msg.sender;
    }

    function isUser(address _user) internal returns (bool) {
        uint size;
        assembly {
            size := extcodesize(_user)
        }
        return size == 0;
    }

    function mint() public isInited {
        require(!_minted[msg.sender]);
        _balances[msg.sender] = 300;
        _minted[msg.sender] = true;
    }

    function isSolved() public isInited {
        if (_total_stocks[keccak256("codegate")] == 0) {
            emit solved(msg.sender);
            address payable addr = payable(address(0));
            selfdestruct(addr);
        }
    }
}
