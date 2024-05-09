// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { MerkleAirdrop, IERC20 } from "../src/MerkleAirdrop.sol";
import { AirdropToken } from "./mocks/AirdropToken.sol";
import { _CheatCodes } from "./mocks/CheatCodes.t.sol";
import { Test } from "../lib/forge-std/src/Test.sol";

// added sp we can use a special expectRevert in a test
import { IERC20Errors } from "@openzeppelin/contracts//interfaces/draft-IERC6093.sol";
// so that we can test on the forked network with real USDC contract
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MerkleAirdropTest_forkedTests is Test {
    MerkleAirdrop public airdrop;
    //AirdropToken public token;

    address public UsdcAddress = 0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4;
    IERC20 public token;

    // @note merkleRoot is correct here but incorrect in the deploy script
    bytes32 public merkleRoot = 0x3b2e22da63ae414086bec9c9da6b685f790c6fab200c7918f2879f08793d77bd;

    _CheatCodes cheatCodes = _CheatCodes(VM_ADDRESS);
    uint256 amountToCollect = (25 * 1e6); // 25.000000
    uint256 amountToSend = amountToCollect * 4;
    address collectorOne = 0x20F41376c713072937eb02Be70ee1eD0D639966C;

    // @note A complete proof of inclusion for a Merkle tree typically requires more than one hash value
    // @note Proofs are correct (created with correct amount 25*1e5)
    bytes32 proofOne = 0x32cee63464b09930b5c3f59f955c86694a4c640a03aa57e6f743d8a3ca5c8838;
    bytes32 proofTwo = 0x8ff683185668cbe035a18fccec4080d7a0331bb1bbc532324f40501de5e8ea5c;
    bytes32[] proof = [proofOne, proofTwo];

    // added:
    address collectorTwo = 0x277D26a45Add5775F21256159F089769892CEa5B;
    bytes32 proofOne_2 = 0x2683f462a4457349d6d7ef62d4208ef42c89c2cff9543cd8292d9269d832c3e8;
    bytes32 proofTwo_2 = 0xdcad361f30c4a5b102a90b4ec310ffd75c577ccdff1c678adb20a6f02e923366;
    bytes32[] proof_2 = [proofOne_2, proofTwo_2];

    address collectorThree = 0x0c8Ca207e27a1a8224D1b602bf856479b03319e7;
    bytes32 proofOne_3 = 0xee1cda884ead2c9f34338f48263e7edd6e5f35bf4f09c9c0930d995911004eed;
    bytes32 proofTwo_3 = 0x8ff683185668cbe035a18fccec4080d7a0331bb1bbc532324f40501de5e8ea5c;
    bytes32[] proof_3 = [proofOne_3, proofTwo_3];

    address collectorFour = 0xf6dBa02C01AF48Cf926579F77C9f874Ca640D91D;
    bytes32 proofOne_4 = 0x1e6784ff835523401f4db6e3ab48fa5bdf523a46a5bc0410a5639d837352b194;
    bytes32 proofTwo_4 = 0xdcad361f30c4a5b102a90b4ec310ffd75c577ccdff1c678adb20a6f02e923366;
    bytes32[] proof_4 = [proofOne_4, proofTwo_4];

    address deployerAddress = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;

    function setUp() public {
        //token = new AirdropToken();
        token = IERC20(0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4);
        vm.prank(deployerAddress);
        airdrop = new MerkleAirdrop(merkleRoot, token);
        //token.mint(address(this), amountToSend);
        //token.transfer(address(airdrop), amountToSend);
        deal(address(token), address(airdrop), amountToSend);
    }

    function testUsersCanClaim() public {
        uint256 startingBalance = token.balanceOf(collectorOne);
        vm.deal(collectorOne, airdrop.getFee());

        vm.startPrank(collectorOne);
        airdrop.claim{ value: airdrop.getFee() }(collectorOne, amountToCollect, proof);
        vm.stopPrank();

        uint256 endingBalance = token.balanceOf(collectorOne);
        assertEq(endingBalance - startingBalance, amountToCollect);
    }

    // @audit
    // The ffi capability allows test scripts to execute arbitrary code at the operating system level,
    // which can be highly risky if the test scripts are malicious or if they contain vulnerable code
    // that could be exploited. Here’s why caution is necessary.
    // @note Turn this off in foundry.toml. Do this before calling make, as it could include a call to test
    function testPwned() public {
        // creates an array of strings for commands to be executed on the system's command lin
        string[] memory cmds = new string[](2);
        // used in Unix-like operating systems to create a new empty file or to update the timestamp on an existing
        // file.
        cmds[0] = "touch";
        // appends the filename to the touch command, effectively creating an empty file named "youve-been-pwned"
        cmds[1] = string.concat("youve-been-pwned");
        cheatCodes.ffi(cmds);
    }

    // @audit bug:
    function testSameUserCanClaimMoreWithMultipleClaims() public {
        uint256 noClaims = 3;
        uint256 startingBalance = token.balanceOf(collectorOne);
        vm.deal(collectorOne, noClaims * airdrop.getFee());

        vm.startPrank(collectorOne);
        for (uint256 i = 0; i < noClaims; i++) {
            airdrop.claim{ value: airdrop.getFee() }(collectorOne, amountToCollect, proof);
        }
        vm.stopPrank();

        uint256 endingBalance = token.balanceOf(collectorOne);
        assertEq(endingBalance - startingBalance, amountToCollect * noClaims);
    }

    // NOT a bug
    function testAnyUserCanClaim() public {
        address user = makeAddr("user");
        uint256 startingBalance = token.balanceOf(user);

        vm.deal(user, airdrop.getFee());

        vm.startPrank(user);
        airdrop.claim{ value: airdrop.getFee() }(collectorOne, amountToCollect, proof);
        vm.stopPrank();

        uint256 endingBalance = token.balanceOf(user);
        assertEq(endingBalance - startingBalance, amountToCollect);
    }

    function testAllCollectorsCanClaim() public {
        uint256 startingBalanceOne = token.balanceOf(collectorOne);
        uint256 startingBalanceTwo = token.balanceOf(collectorTwo);
        uint256 startingBalanceThree = token.balanceOf(collectorThree);
        uint256 startingBalanceFour = token.balanceOf(collectorFour);

        vm.deal(collectorOne, airdrop.getFee());
        vm.deal(collectorTwo, airdrop.getFee());
        vm.deal(collectorThree, airdrop.getFee());
        vm.deal(collectorFour, airdrop.getFee());

        vm.startPrank(collectorOne);
        airdrop.claim{ value: airdrop.getFee() }(collectorOne, amountToCollect, proof);
        vm.stopPrank();

        vm.startPrank(collectorTwo);
        airdrop.claim{ value: airdrop.getFee() }(collectorTwo, amountToCollect, proof_2);
        vm.stopPrank();

        vm.startPrank(collectorThree);
        airdrop.claim{ value: airdrop.getFee() }(collectorThree, amountToCollect, proof_3);
        vm.stopPrank();

        vm.startPrank(collectorFour);
        airdrop.claim{ value: airdrop.getFee() }(collectorFour, amountToCollect, proof_4);
        vm.stopPrank();

        uint256 endingBalanceOne = token.balanceOf(collectorOne);
        uint256 endingBalanceTwo = token.balanceOf(collectorTwo);
        uint256 endingBalanceThree = token.balanceOf(collectorThree);
        uint256 endingBalanceFour = token.balanceOf(collectorFour);

        assertEq(endingBalanceOne - startingBalanceOne, amountToCollect);
        assertEq(endingBalanceTwo - startingBalanceTwo, amountToCollect);
        assertEq(endingBalanceThree - startingBalanceThree, amountToCollect);
        assertEq(endingBalanceFour - startingBalanceFour, amountToCollect);
    }

    function testCanWithdraw() public {
        vm.deal(collectorOne, airdrop.getFee());

        vm.startPrank(collectorOne);
        airdrop.claim{ value: airdrop.getFee() }(collectorOne, amountToCollect, proof);
        vm.stopPrank();

        address user = makeAddr("user");
        vm.prank(user);
        vm.expectRevert();
        airdrop.claimFees();

        vm.prank(deployerAddress);
        airdrop.claimFees();
    }

    // import IERC20: import { MerkleAirdrop, IERC20 } from "../src/MerkleAirdrop.sol";
    function testIncorrectMerkleRoot() public {
        // Deploy script and test file use different setups.
        // To demonstrate the vulnerability, we use the same setup in this test as in the deploy script.

        // the test file had the correct Merkle root
        // to demonstrate the bug, re-set it to the incorrect value used in Deploy.s.sol
        bytes32 merkleRoot_bad = 0xf69aaa25bd4dd10deb2ccd8235266f7cc815f6e9d539e9f4d47cae16e0c36a05;

        // the test file has the correct airdrop contract
        // to demonstrate the bug, we need an airdrop contract the is deployed with the wrong root
        // as done in Deploy.s.sol
        MerkleAirdrop airdrop_bad = new MerkleAirdrop(merkleRoot_bad, token);

        // the test file had the correct proof
        // to demonstrate the bug, set it to the incorrect value that the incorrect makeMerkle.js generates
        bytes32 proofOne_bad = 0x4fd31fee0e75780cd67704fbc43caee70fddcaa43631e2e1bc9fb233fada2394;
        bytes32 proofTwo_bad = 0xc88d18957ad6849229355580c1bde5de3ae3b78024db2e6c2a9ad674f7b59f84;
        bytes32[] memory proof_bad = new bytes32[](2);
        proof_bad[0] = proofOne_bad;
        proof_bad[1] = proofTwo_bad;

        // setting up balances
        vm.deal(collectorOne, airdrop_bad.getFee());
        deal(address(token), address(airdrop_bad), 4 * 25 * 1e6);
        //token.mint(address(airdrop_bad), 4 * 25 * 1e6);
        assert(IERC20(token).balanceOf(address(airdrop_bad)) == 4 * 25 * 1e6);

        // @note SCENARIO 1: collector tries to collect 25 USDC
        // but the trx fails as a different value is encoded in the Merkle root
        vm.prank(collectorOne);
        // expectRevert would expect a revert for this call which is not we want, so
        // moving this out from the airdrop.claim call
        uint256 fee = airdrop_bad.getFee();
        vm.expectRevert(MerkleAirdrop.MerkleAirdrop__InvalidProof.selector);
        airdrop_bad.claim{ value: fee }(collectorOne, amountToCollect, proof_bad);

        // add more USDC to the airdrop contract
        //vm.deal(address(airdrop), 25*1e12)

        // @note SCENARIO 2: collector tries to collect the value that is actually encoded in the Markle root
        // but trx reverts because the airdrop contract does not have enough balance

        //setting up balances
        vm.deal(collectorOne, airdrop_bad.getFee());
        uint256 amountEncodedInRoot = 25 * 1e18;
        vm.prank(collectorOne);
        vm.deal(address(airdrop_bad), amountEncodedInRoot);

        // encode expected error
        address expectedAddress = 0x6914631e3e71Bc75A1664e3BaEE140CC05cAE18B;
        uint256 currentBalance = 100_000_000; // 1e8
        uint256 requiredBalance = 25_000_000_000_000_000_000; // 25e18
        // Encode the expected revert reason
        // note need import: import { IERC20Errors } from "@openzeppelin/contracts//interfaces/draft-IERC6093.sol";
        bytes memory encodedRevertReason = abi.encodeWithSelector(
            IERC20Errors.ERC20InsufficientBalance.selector, expectedAddress, currentBalance, requiredBalance
        );

        vm.expectRevert(encodedRevertReason);
        airdrop_bad.claim{ value: fee }(collectorOne, amountEncodedInRoot, proof_bad);
    }
}
