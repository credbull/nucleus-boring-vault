// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.21;

import { BoringVault } from "src/base/BoringVault.sol";
import { ManagerWithMerkleVerification } from "src/base/Roles/ManagerWithMerkleVerification.sol";

import { ERC20 } from "@solmate/tokens/ERC20.sol";
import { EtherFiLiquidDecoderAndSanitizer } from "src/base/DecodersAndSanitizers/EtherFiLiquidDecoderAndSanitizer.sol";
import { RolesAuthority, Authority } from "@solmate/auth/authorities/RolesAuthority.sol";

import { ManagerTestBase, Roles } from "./ManagerTestBase.t.sol";
import { SimpleUSDC } from "@credbull-test/test/token/SimpleUSDC.t.sol";

import { Test, stdStorage, StdStorage, stdError, console } from "@forge-std/Test.sol";

contract ManagerTokenTest is Test, ManagerTestBase {
    BoringVault private _boringVault;
    ManagerWithMerkleVerification private _manager;
    address public _rawDataDecoderAndSanitizerAddr;

    SimpleUSDC private _usdc;
    SimpleUSDC private _usdt;

    function setUp() external {
        _boringVault = new BoringVault(_admin, "Test Boring Vault", "TBV", 18);
        _manager = new ManagerWithMerkleVerification(_admin, address(_boringVault), _zeroAddress);
        _rawDataDecoderAndSanitizerAddr =
            address(new EtherFiLiquidDecoderAndSanitizer(address(_boringVault), uniswapV3NonFungiblePositionManager));
        _setupAuth(_boringVault, _manager);

        _usdc = new SimpleUSDC(_admin, 1_000_000_000 * 10 ** 6);
        _usdt = new SimpleUSDC(_admin, 1_000_000_000 * 10 ** 6);
    }

    function test__ERC4626Manager__ApproveToken() external {
        address usdcSpender = makeAddr("usdcSpender");
        uint256 depositAmount = 1234;

        ManageLeaf[] memory leafs = new ManageLeaf[](1);
        leafs[0] = ManageLeaf(address(_usdc), false, "approve(address,uint256)", new address[](1));
        leafs[0].argumentAddresses[0] = usdcSpender;

        bytes32[][] memory manageTree = _generateMerkleTree(leafs);

        vm.prank(_admin);
        _manager.setManageRoot(_strategist, manageTree[leafs.length > 1 ? 1 : 0][0]);

        address[] memory targets = new address[](1);
        targets[0] = address(_usdc);

        bytes[] memory targetData = new bytes[](1);
        targetData[0] = abi.encodeWithSelector(ERC20.approve.selector, usdcSpender, depositAmount);

        (bytes32[][] memory manageProofs) = _getProofsUsingTree(leafs, manageTree);

        uint256[] memory values = new uint256[](1);

        address[] memory decodersAndSanitizers = new address[](1);
        decodersAndSanitizers[0] = _rawDataDecoderAndSanitizer();

        uint256 gas = gasleft();

        vm.startPrank(_strategist);
        _manager.manageVaultWithMerkleVerification(manageProofs, decodersAndSanitizers, targets, targetData, values);
        console.log("Gas used", gas - gasleft());
        vm.stopPrank();

        assertEq(_usdc.allowance(address(_boringVault), usdcSpender), depositAmount, "USDC should have an allowance");
    }

    function test__ERC4626Manager__ApproveMultipleTokens() external {
        address usdcSpender = makeAddr("usdcSpender");
        address usdtTo = makeAddr("usdtSpender");

        uint256 depositAmount = 1234;

        ManageLeaf[] memory leafs = new ManageLeaf[](2);
        leafs[0] = ManageLeaf(address(_usdc), false, "approve(address,uint256)", new address[](1));
        leafs[0].argumentAddresses[0] = usdcSpender;
        leafs[1] = ManageLeaf(address(_usdt), false, "approve(address,uint256)", new address[](1));
        leafs[1].argumentAddresses[0] = usdtTo;

        bytes32[][] memory manageTree = _generateMerkleTree(leafs);

        vm.prank(_admin);
        _manager.setManageRoot(_strategist, manageTree[1][0]);

        address[] memory targets = new address[](2);
        targets[0] = address(_usdc);
        targets[1] = address(_usdt);

        bytes[] memory targetData = new bytes[](2);
        targetData[0] = abi.encodeWithSelector(ERC20.approve.selector, usdcSpender, depositAmount);
        targetData[1] = abi.encodeWithSelector(ERC20.approve.selector, usdtTo, depositAmount);

        (bytes32[][] memory manageProofs) = _getProofsUsingTree(leafs, manageTree);

        uint256[] memory values = new uint256[](2);

        address[] memory decodersAndSanitizers = new address[](2);
        decodersAndSanitizers[0] = _rawDataDecoderAndSanitizer();
        decodersAndSanitizers[1] = _rawDataDecoderAndSanitizer();

        uint256 gas = gasleft();

        vm.startPrank(_strategist);
        _manager.manageVaultWithMerkleVerification(manageProofs, decodersAndSanitizers, targets, targetData, values);
        console.log("Gas used", gas - gasleft());
        vm.stopPrank();

        assertEq(_usdc.allowance(address(_boringVault), usdcSpender), depositAmount, "USDC should have an allowance");
        assertEq(_usdt.allowance(address(_boringVault), usdtTo), depositAmount, "USDT should have have an allowance");
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
