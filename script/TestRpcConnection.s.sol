// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";

contract TestRPCConnection is Script {
    function run() public {
        console.log("Testing RPC connection...");
        uint256 latestBlock = vm.getBlockNumber();
        console.log("Latest block number is:", latestBlock);
    }
}
