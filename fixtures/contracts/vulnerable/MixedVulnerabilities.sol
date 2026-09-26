// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MixedVulnerabilities {
    mapping(address => uint256) public balance;
    address public owner;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw(address payable recipient, uint256 amount) external {
        require(balance[msg.sender] >= amount);
        (bool ok, ) = recipient.call{value: amount}("");
        balance[msg.sender] -= amount;
        ok;
    }

    function auth() external view returns (bool) {
        return tx.origin == owner;
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    function random() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number - 1))));
    }

    function execute(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    function setOwner(address nextOwner) external {
        owner = nextOwner;
    }
}
