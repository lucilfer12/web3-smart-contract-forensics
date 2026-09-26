// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GuardedVault {
    mapping(address => uint256) public balance;
    address public immutable owner;
    bool private locked;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok);
    }

    function setOwner(address nextOwner) external onlyOwner {
        // owner is immutable; placeholder for interface parity in fixture.
        nextOwner;
    }
}
