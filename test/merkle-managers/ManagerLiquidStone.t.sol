// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.21;

import { BoringVault } from "src/base/BoringVault.sol";
import { ManagerWithMerkleVerification } from "src/base/Roles/ManagerWithMerkleVerification.sol";

import { ERC20 } from "@solmate/tokens/ERC20.sol";
import { EtherFiLiquidDecoderAndSanitizer } from "src/base/DecodersAndSanitizers/EtherFiLiquidDecoderAndSanitizer.sol";
import { RolesAuthority, Authority } from "@solmate/auth/authorities/RolesAuthority.sol";

import { ManagerTestBase, Roles } from "./ManagerTestBase.t.sol";
import { SimpleUSDC } from "@credbull-test/test/token/SimpleUSDC.t.sol";

// ===== Credbull ====
import {
    LiquidContinuousMultiTokenVaultTestBase,
    LiquidContinuousMultiTokenVault,
    TestParamSet
} from "@credbull-test/test/yield/LiquidContinuousMultiTokenVaultTestBase.t.sol";
// ===== end Credbull ====

import { Test, stdStorage, StdStorage, stdError, console } from "@forge-std/Test.sol";

contract ManagerLiquidStone is ManagerTestBase, LiquidContinuousMultiTokenVaultTestBase {
    BoringVault private _boringVault;
    ManagerWithMerkleVerification private _manager;
    address public _rawDataDecoderAndSanitizerAddr;

    function test__ManagerLiquidStone__Deposit() external {
        uint256 period = 10;

        _boringVault = new BoringVault(_admin, "Test Boring Vault", "TBV", 18);
        _manager = new ManagerWithMerkleVerification(_admin, address(_boringVault), _zeroAddress);
        _rawDataDecoderAndSanitizerAddr =
            address(new EtherFiLiquidDecoderAndSanitizer(address(_boringVault), uniswapV3NonFungiblePositionManager));
        _setupAuth(_boringVault, _manager);

        assertEq(0, _liquidVault.totalAssets());

        // ---------------- setup deposit ----------------
        TestParamSet.TestParam memory testParams =
            TestParamSet.TestParam({ principal: 2000 * _scale, depositPeriod: 10, redeemPeriod: 71 });

        deal(_liquidVault.asset(), address(_boringVault), testParams.principal);

        // ---------------- deposit ----------------
        _liquidVerifier._warpToPeriod(_toIVault(_liquidVault), testParams.depositPeriod);

        // set up the address arguments
        ManageLeaf[] memory leafs = new ManageLeaf[](2);
        leafs[0] = ManageLeaf(_liquidVault.asset(), false, "approve(address,uint256)", new address[](1));
        leafs[0].argumentAddresses[0] = address(_liquidVault);
        leafs[1] = ManageLeaf(address(_liquidVault), false, "deposit(uint256,address)", new address[](1));
        leafs[1].argumentAddresses[0] = address(_boringVault);

        bytes32[][] memory manageTree = _generateMerkleTree(leafs);

        vm.prank(_admin);
        _manager.setManageRoot(_strategist, manageTree[1][0]);

        address[] memory targets = new address[](2);
        targets[0] = leafs[0].target;
        targets[1] = leafs[1].target;

        // TODO - use the selector, e.g. LiquidContinuousMultiTokenVault.requestDeposit.selector
        bytes[] memory targetData = new bytes[](2);
        targetData[0] = abi.encodeWithSelector(ERC20.approve.selector, address(_liquidVault), testParams.principal);
        targetData[1] = abi.encodeWithSignature("deposit(uint256,address)", testParams.principal, address(_boringVault));

        (bytes32[][] memory manageProofs) = _getProofsUsingTree(leafs, manageTree);

        uint256[] memory values = new uint256[](2);

        // TODO - enhance the decoder and sanitizer to add requestDeposit()
        address[] memory decodersAndSanitizers = new address[](2);
        decodersAndSanitizers[0] = _rawDataDecoderAndSanitizer();
        decodersAndSanitizers[1] = _rawDataDecoderAndSanitizer();

        vm.startPrank(_strategist);
        _manager.manageVaultWithMerkleVerification(manageProofs, decodersAndSanitizers, targets, targetData, values);
        vm.stopPrank();

        // verify deposit
        assertEq(testParams.principal, _liquidVault.totalAssets());
        assertEq(testParams.principal, _liquidVault.balanceOf(address(_boringVault), _liquidVault.currentPeriod()));

        // TODO - call redeem

        // TODO - verify redeem
    }

    function _rawDataDecoderAndSanitizer()
        internal
        view
        virtual
        override
        returns (address rawDataDecoderAndSanitizer_)
    {
        return _rawDataDecoderAndSanitizerAddr;
    }
}
