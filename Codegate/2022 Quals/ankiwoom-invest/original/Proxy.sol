// SPDX-License-Identifier: MIT

pragma solidity 0.8.11;


contract Proxy {
    address implementation;
    address owner;

    struct log {
        bytes12 time;
        address sender;
    }
    log info;

    constructor(address _target) {
        owner = msg.sender;
        implementation = _target;
    }

    function setImplementation(address _target) public {
        require(msg.sender == owner);
        implementation = _target;
    }

    function _delegate(address _target) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())

            let result := delegatecall(gas(), _target, 0, calldatasize(), 0, 0)

            returndatacopy(0, 0, returndatasize())

            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    function _implementation() internal view returns (address) {
        return implementation;
    }

    function _fallback() internal {
        _beforeFallback();
        _delegate(_implementation());
    }

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }

    function _beforeFallback() internal {
        info.time = bytes12(uint96(block.timestamp));
        info.sender = msg.sender;
    }
}
