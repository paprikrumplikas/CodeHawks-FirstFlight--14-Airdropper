// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { MerkleAirdrop, IERC20 } from "../src/MerkleAirdrop.sol";
import { Script } from "../lib/forge-std/src/Script.sol";

contract Deploy is Script {
    // @audit incorrect address. 0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4
    address public s_zkSyncUSDC = 0x1D17CbCf0D6d143135be902365d2e5E2a16538d4;
    // @note this is an incorrect Merkle Root. For this, the amount is 25*1e18, not 25*1e6
    bytes32 public s_merkleRoot = 0xf69aaa25bd4dd10deb2ccd8235266f7cc815f6e9d539e9f4d47cae16e0c36a05;
    // @note correct Merkle root
    //bytes32 public s_merkleRoot = 0x3b2e22da63ae414086bec9c9da6b685f790c6fab200c7918f2879f08793d77bd;
    // 4 users, 25 USDC each
    uint256 public s_amountToAirdrop = 4 * (25 * 1e6);

    // Deploy the airdropper
    // @audit deployer address does not have 100 USDC. Does it have fees?
    function run() public {
        vm.startBroadcast();
        MerkleAirdrop airdrop = deployMerkleDropper(s_merkleRoot, IERC20(s_zkSyncUSDC));
        // Send USDC -> Merkle Air Dropper
        // e here we have the correct address
        IERC20(0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4).transfer(address(airdrop), s_amountToAirdrop);
        vm.stopBroadcast();
    }

    function deployMerkleDropper(bytes32 merkleRoot, IERC20 zkSyncUSDC) public returns (MerkleAirdrop) {
        return (new MerkleAirdrop(merkleRoot, zkSyncUSDC));
    }
}
