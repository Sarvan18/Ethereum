// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/**
 * @dev External interface of AccessControl declared to support ERC-165 detection.
 */
interface IAccessControl {
    /**
     * @dev The `account` is missing a role.
     */
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    /**
     * @dev The caller of a function is not the expected one.
     *
     * NOTE: Don't confuse with {AccessControlUnauthorizedAccount}.
     */
    error AccessControlBadConfirmation();

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted to signal this.
     */
    event RoleAdminChanged(
        bytes32 indexed role,
        bytes32 indexed previousAdminRole,
        bytes32 indexed newAdminRole
    );

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call. This account bears the admin role (for the granted role).
     * Expected in cases where the role was granted using the internal {AccessControl-_grantRole}.
     */
    event RoleGranted(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(
        bytes32 indexed role,
        address indexed account,
        address indexed sender
    );

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account)
        external
        view
        returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     */
    function renounceRole(bytes32 role, address callerConfirmation) external;
}

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);
}

/**
 * @dev Interface for the optional metadata functions from the ERC-20 standard.
 */
interface IERC20Metadata is IERC20 {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);
}

/**
 * @title IERC1363
 * @dev Interface of the ERC-1363 standard as defined in the https://eips.ethereum.org/EIPS/eip-1363[ERC-1363].
 *
 * Defines an extension interface for ERC-20 tokens that supports executing code on a recipient contract
 * after `transfer` or `transferFrom`, or code on a spender contract after `approve`, in a single transaction.
 */
interface IERC1363 is IERC20, IERC165 {
    /*
     * Note: the ERC-165 identifier for this interface is 0xb0202a11.
     * 0xb0202a11 ===
     *   bytes4(keccak256('transferAndCall(address,uint256)')) ^
     *   bytes4(keccak256('transferAndCall(address,uint256,bytes)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256)')) ^
     *   bytes4(keccak256('transferFromAndCall(address,address,uint256,bytes)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256)')) ^
     *   bytes4(keccak256('approveAndCall(address,uint256,bytes)'))
     */

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(address to, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferAndCall(
        address to,
        uint256 value,
        bytes calldata data
    ) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(
        address from,
        address to,
        uint256 value
    ) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the allowance mechanism
     * and then calls {IERC1363Receiver-onTransferReceived} on `to`.
     * @param from The address which you want to send tokens from.
     * @param to The address which you want to transfer to.
     * @param value The amount of tokens to be transferred.
     * @param data Additional data with no specified format, sent in call to `to`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function transferFromAndCall(
        address from,
        address to,
        uint256 value,
        bytes calldata data
    ) external returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(address spender, uint256 value)
        external
        returns (bool);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens and then calls {IERC1363Spender-onApprovalReceived} on `spender`.
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     * @param data Additional data with no specified format, sent in call to `spender`.
     * @return A boolean value indicating whether the operation succeeded unless throwing.
     */
    function approveAndCall(
        address spender,
        uint256 value,
        bytes calldata data
    ) external returns (bool);
}

interface AggregatorV3Interface {
    function decimals() external view returns (uint8);

    function description() external view returns (string memory);

    function version() external view returns (uint256);

    function getRoundData(uint80 _roundId)
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );

    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}

interface IPancakeRouter01 {
    function factory() external pure returns (address);

    function WETH() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    )
        external
        returns (
            uint256 amountA,
            uint256 amountB,
            uint256 liquidity
        );

    function addLiquidityETH(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    )
        external
        payable
        returns (
            uint256 amountToken,
            uint256 amountETH,
            uint256 liquidity
        );

    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB);

    function removeLiquidityETH(
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountToken, uint256 amountETH);

    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline,
        bool approveMax,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 amountA, uint256 amountB);

    function removeLiquidityETHWithPermit(
        address token,
        uint256 liquidity,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline,
        bool approveMax,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 amountToken, uint256 amountETH);

    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapTokensForExactTokens(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);

    function swapTokensForExactETH(
        uint256 amountOut,
        uint256 amountInMax,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);

    function swapETHForExactTokens(
        uint256 amountOut,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);

    function quote(
        uint256 amountA,
        uint256 reserveA,
        uint256 reserveB
    ) external pure returns (uint256 amountB);

    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) external pure returns (uint256 amountOut);

    function getAmountIn(
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut
    ) external pure returns (uint256 amountIn);

    function getAmountsOut(uint256 amountIn, address[] calldata path)
        external
        view
        returns (uint256[] memory amounts);

    function getAmountsIn(uint256 amountOut, address[] calldata path)
        external
        view
        returns (uint256[] memory amounts);
}

interface ILaunchpadError {
    error InvalidOption();

    error InvalidTime();

    error NotZeroValue();

    error MinMaxCollapse();

    error InvalidUser();

    error InvalidAmount();
}

/**
 * @dev Helper to make usage of the `CREATE2` EVM opcode easier and safer.
 * `CREATE2` can be used to compute in advance the address where a smart
 * contract will be deployed, which allows for interesting new mechanisms known
 * as 'counterfactual interactions'.
 *
 * See the https://eips.ethereum.org/EIPS/eip-1014#motivation[EIP] for more
 * information.
 */
library Create2 {
    /**
     * @dev Deploys a contract using `CREATE2`. The address where the contract
     * will be deployed can be known in advance via {computeAddress}.
     *
     * The bytecode for a contract can be obtained from Solidity with
     * `type(contractName).creationCode`.
     *
     * Requirements:
     *
     * - `bytecode` must not be empty.
     * - `salt` must have not been used for `bytecode` already.
     * - the factory must have a balance of at least `amount`.
     * - if `amount` is non-zero, `bytecode` must have a `payable` constructor.
     */
    function deploy(
        uint256 amount,
        bytes32 salt,
        bytes memory bytecode
    ) internal returns (address addr) {
        require(
            address(this).balance >= amount,
            "Create2: insufficient balance"
        );
        require(bytecode.length != 0, "Create2: bytecode length is zero");
        /// @solidity memory-safe-assembly
        assembly {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Create2: Failed on deploy");
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy}. Any change in the
     * `bytecodeHash` or `salt` will result in a new destination address.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash)
        internal
        view
        returns (address)
    {
        return computeAddress(salt, bytecodeHash, address(this));
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy} from a contract located at
     * `deployer`. If `deployer` is this contract's address, returns the same value as {computeAddress}.
     */
    function computeAddress(
        bytes32 salt,
        bytes32 bytecodeHash,
        address deployer
    ) internal pure returns (address addr) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40) // Get free memory pointer

            // |                   | ↓ ptr ...  ↓ ptr + 0x0B (start) ...  ↓ ptr + 0x20 ...  ↓ ptr + 0x40 ...   |
            // |-------------------|---------------------------------------------------------------------------|
            // | bytecodeHash      |                                                        CCCCCCCCCCCCC...CC |
            // | salt              |                                      BBBBBBBBBBBBB...BB                   |
            // | deployer          | 000000...0000AAAAAAAAAAAAAAAAAAA...AA                                     |
            // | 0xFF              |            FF                                                             |
            // |-------------------|---------------------------------------------------------------------------|
            // | memory            | 000000...00FFAAAAAAAAAAAAAAAAAAA...AABBBBBBBBBBBBB...BBCCCCCCCCCCCCC...CC |
            // | keccak(start, 85) |            ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ |

            mstore(add(ptr, 0x40), bytecodeHash)
            mstore(add(ptr, 0x20), salt)
            mstore(ptr, deployer) // Right-aligned with 12 preceding garbage bytes
            let start := add(ptr, 0x0b) // The hashed data starts at the final garbage byte which we will set to 0xff
            mstore8(start, 0xff)
            addr := keccak256(start, 85)
        }
    }
}

library BytesLibrary {
    function toString(bytes32 value) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i * 2] = alphabet[uint8(value[i] >> 4)];
            str[1 + i * 2] = alphabet[uint8(value[i] & 0x0f)];
        }
        return string(str);
    }

    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        bytes32 fullMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        return ecrecover(fullMessage, v, r, s);
    }
}

/**
 * @title SafeERC20
 * @dev Wrappers around ERC-20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    /**
     * @dev An operation with an ERC-20 token failed.
     */
    error SafeERC20FailedOperation(address token);

    /**
     * @dev Indicates a failed `decreaseAllowance` request.
     */
    error SafeERC20FailedDecreaseAllowance(
        address spender,
        uint256 currentAllowance,
        uint256 requestedDecrease
    );

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(
            token,
            abi.encodeCall(token.transferFrom, (from, to, value))
        );
    }

    /**
     * @dev Variant of {safeTransfer} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal returns (bool) {
        return
            _callOptionalReturnBool(
                token,
                abi.encodeCall(token.transfer, (to, value))
            );
    }

    /**
     * @dev Variant of {safeTransferFrom} that returns a bool instead of reverting if the operation is not successful.
     */
    function trySafeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal returns (bool) {
        return
            _callOptionalReturnBool(
                token,
                abi.encodeCall(token.transferFrom, (from, to, value))
            );
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `requestedDecrease`. If `token` returns no
     * value, non-reverting calls are assumed to be successful.
     *
     * IMPORTANT: If the token implements ERC-7674 (ERC-20 with temporary allowance), and if the "client"
     * smart contract uses ERC-7674 to set temporary allowances, then the "client" smart contract should avoid using
     * this function. Performing a {safeIncreaseAllowance} or {safeDecreaseAllowance} operation on a token contract
     * that has a non-zero temporary allowance (for that particular owner-spender) will result in unexpected behavior.
     */
    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 requestedDecrease
    ) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(
                    spender,
                    currentAllowance,
                    requestedDecrease
                );
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     *
     * NOTE: If the token implements ERC-7674, this function will not modify any temporary allowance. This function
     * only sets the "standard" allowance. Any temporary allowance will remain active, in addition to the value being
     * set here.
     */
    function forceApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        bytes memory approvalCall = abi.encodeCall(
            token.approve,
            (spender, value)
        );

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(
                token,
                abi.encodeCall(token.approve, (spender, 0))
            );
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Performs an {ERC1363} transferAndCall, with a fallback to the simple {ERC20} transfer if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferAndCallRelaxed(
        IERC1363 token,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        if (to.code.length == 0) {
            safeTransfer(token, to, value);
        } else if (!token.transferAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} transferFromAndCall, with a fallback to the simple {ERC20} transferFrom if the target
     * has no code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * Reverts if the returned value is other than `true`.
     */
    function transferFromAndCallRelaxed(
        IERC1363 token,
        address from,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        if (to.code.length == 0) {
            safeTransferFrom(token, from, to, value);
        } else if (!token.transferFromAndCall(from, to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Performs an {ERC1363} approveAndCall, with a fallback to the simple {ERC20} approve if the target has no
     * code. This can be used to implement an {ERC721}-like safe transfer that rely on {ERC1363} checks when
     * targeting contracts.
     *
     * NOTE: When the recipient address (`to`) has no code (i.e. is an EOA), this function behaves as {forceApprove}.
     * Opposedly, when the recipient address (`to`) has code, this function only attempts to call {ERC1363-approveAndCall}
     * once without retrying, and relies on the returned value to be true.
     *
     * Reverts if the returned value is other than `true`.
     */
    function approveAndCallRelaxed(
        IERC1363 token,
        address to,
        uint256 value,
        bytes memory data
    ) internal {
        if (to.code.length == 0) {
            forceApprove(token, to, value);
        } else if (!token.approveAndCall(to, value, data)) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturnBool} that reverts if call fails to meet the requirements.
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            let success := call(
                gas(),
                token,
                0,
                add(data, 0x20),
                mload(data),
                0,
                0x20
            )
            // bubble errors
            if iszero(success) {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
            returnSize := returndatasize()
            returnValue := mload(0)
        }

        if (
            returnSize == 0 ? address(token).code.length == 0 : returnValue != 1
        ) {
            revert SafeERC20FailedOperation(address(token));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silently catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20 token, bytes memory data)
        private
        returns (bool)
    {
        bool success;
        uint256 returnSize;
        uint256 returnValue;
        assembly ("memory-safe") {
            success := call(
                gas(),
                token,
                0,
                add(data, 0x20),
                mload(data),
                0,
                0x20
            )
            returnSize := returndatasize()
            returnValue := mload(0)
        }
        return
            success &&
            (
                returnSize == 0
                    ? address(token).code.length > 0
                    : returnValue == 1
            );
    }
}

library LaunchpadTypes {
    enum SaleType {
        presale,
        fairLaunch
    }

    enum RefundOption {
        Burn,
        ReturnToOwner
    }

    enum ClaimType {
        NormalClaim,
        VestingClaim
    }

    struct ClaimTypeDetail {
        ClaimType claimType;
        uint256 vestRate;
        uint256 vestingInterval;
    }

    struct ProjectOwner {
        address lpToken;
        uint256 usdValueClaimed;
        uint256 lpTokenOwned;
        uint256 liquidityTimestamp;
        uint256 liquidityLockDuriation;
        bool isClaimed;
    }

    struct SaleDetails {
        SaleType saleType;
        address token;
        address pairToken;
        uint256 startTime;
        uint256 endTime;
        uint256 softCap;
        uint256 hardCap;
        uint256 allocationForSale;
    }

    struct ProjectInfo {
        address owner;
        SaleDetails saleDetails;
        RefundOption refundOption;
        uint256 liqudityPercent;
        uint256 totalAmount;
        ClaimTypeDetail claimTypeDetail;
    }

    struct UserDetails {
        address[] investedAsset;
        uint256[] investedAmount;
        uint256[] investedOriginalAmount;
        uint256 claimedAmount;
        bool claimed;
        uint256 lastClaimTimestamp;
        uint256 vestingInterval;
    }

    struct LaunchRules {
        uint256 tokenPriceinUSD;
        uint256 minContribution;
        uint256 maxContribution;
    }

    struct PlatformFee {
        address platformOwner;
        address platformSigner;
        uint256 commisonFee;
        uint256 projectPlatformFee;
    }

    struct Sig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }
}

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC-165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165 {
    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        returns (bool)
    {
        return interfaceId == type(IERC165).interfaceId;
    }
}

/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping(address => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override
        returns (bool)
    {
        return
            interfaceId == type(IAccessControl).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account)
        public
        view
        virtual
        returns (bool)
    {
        return _roles[role].hasRole[account];
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
     * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert AccessControlUnauthorizedAccount(account, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account)
        public
        virtual
        onlyRole(getRoleAdmin(role))
    {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account)
        public
        virtual
        onlyRole(getRoleAdmin(role))
    {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address callerConfirmation)
        public
        virtual
    {
        if (callerConfirmation != _msgSender()) {
            revert AccessControlBadConfirmation();
        }

        _revokeRole(role, callerConfirmation);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account)
        internal
        virtual
        returns (bool)
    {
        if (!hasRole(role, account)) {
            _roles[role].hasRole[account] = true;
            emit RoleGranted(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` from `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account)
        internal
        virtual
        returns (bool)
    {
        if (hasRole(role, account)) {
            _roles[role].hasRole[account] = false;
            emit RoleRevoked(role, account, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract Pausable is Context {
    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    bool private _paused;

    /**
     * @dev Initializes the contract in unpaused state.
     */
    constructor() {
        _paused = false;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused() {
        _requirePaused();
        _;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Throws if the contract is paused.
     */
    function _requireNotPaused() internal view virtual {
        require(!paused(), "Pausable: paused");
    }

    /**
     * @dev Throws if the contract is not paused.
     */
    function _requirePaused() internal view virtual {
        require(paused(), "Pausable: not paused");
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}

contract GiantSale is AccessControl, ILaunchpadError {
    AggregatorV3Interface internal priceFeed;

    using SafeERC20 for IERC20;
    using BytesLibrary for bytes32;
    using LaunchpadTypes for *;
    uint256 private _projectId;

    bytes32 public constant PROJECT_OWNER_ROLE =
        keccak256("PROJECT_OWNER_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    mapping(bytes32 => bool) public completed; // 1.completed
    mapping(uint256 => LaunchpadTypes.ProjectInfo) public projects;
    mapping(uint256 => LaunchpadTypes.LaunchRules) public presaleDetails;
    mapping(uint256 => uint256) public totalRaisedInUSD;
    mapping(uint256 => mapping(address => LaunchpadTypes.UserDetails))
        public investorInfo; // ProjectId → User → Contribution
    mapping(address => LaunchpadTypes.ProjectOwner) public projectOwnerDetails;
    mapping(uint256 => LaunchpadTypes.PlatformFee) public platformFee;

    event UserContribution(
        address indexed user,
        uint256 indexed projectId,
        address token,
        uint256 amount,
        uint256 timestamp
    );

    receive() external payable {}

    constructor(
        LaunchpadTypes.ProjectInfo memory _projectInfo,
        LaunchpadTypes.LaunchRules memory _launchRules,
        LaunchpadTypes.PlatformFee memory _platformFee,
        uint256 __projectId,
        uint256 liquidityLockDuriation
    ) {
        if (projects[__projectId].owner != address(0))
            return revert("Already Initialized");
        priceFeed = AggregatorV3Interface(
            0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6
        );
        _projectId = __projectId;
        projects[_projectId] = _projectInfo;
        presaleDetails[_projectId] = _launchRules;
        platformFee[_projectId] = _platformFee;
        projectOwnerDetails[_projectInfo.owner]
            .liquidityLockDuriation = liquidityLockDuriation;
        _grantRole(DEFAULT_ADMIN_ROLE, _platformFee.platformOwner);
        _grantRole(PROJECT_OWNER_ROLE, _projectInfo.owner);
        _grantRole(SIGNER_ROLE, _platformFee.platformSigner);
    }

    function vestClaim(
        address _user,
        uint256 _deadline,
        LaunchpadTypes.Sig memory sig
    ) external {
        require(_user == _msgSender(), "Invalid User");
        require(
            hasRole(
                SIGNER_ROLE,
                validateSaleSignature(_user, 0, _deadline, sig)
            ),
            "Sale : Invalid Signer"
        );
        proceedClaim(_user, 0, true);
    }

    function claim(
        address _user,
        uint256 _amount,
        uint256 _deadline,
        LaunchpadTypes.Sig memory sig
    ) external {
        require(_user == _msgSender(), "Invalid User");
        require(
            hasRole(
                SIGNER_ROLE,
                validateSaleSignature(_user, _amount, _deadline, sig)
            ),
            "Sale : Invalid Signer"
        );
        proceedClaim(_user, _amount, false);
    }

    function claimLiquidity(
        address _user,
        uint256 _amount,
        uint256 _deadline,
        LaunchpadTypes.Sig memory sig
    ) external onlyRole(PROJECT_OWNER_ROLE) {
        require(
            block.timestamp >
                projectOwnerDetails[msg.sender].liquidityTimestamp +
                    projectOwnerDetails[msg.sender].liquidityLockDuriation,
            "Liquidity Locked"
        );
        require(!projectOwnerDetails[msg.sender].isClaimed, "Already Claimed");
        require(
            _amount == projectOwnerDetails[msg.sender].lpTokenOwned,
            "Amount Mismatches"
        );
        require(
            hasRole(
                SIGNER_ROLE,
                validateSaleSignature(_user, _amount, _deadline, sig)
            ),
            "Sale : Invalid Signer"
        );
        projectOwnerDetails[msg.sender].isClaimed = true;
        IERC20(projectOwnerDetails[msg.sender].lpToken).safeTransfer(
            msg.sender,
            projectOwnerDetails[msg.sender].lpTokenOwned
        );
    }

    function addLiquidity(
        address _router,
        address _token,
        uint256 _amount,
        uint256 _deadline,
        bool isGtan,
        LaunchpadTypes.Sig memory sig
    ) external onlyRole(PROJECT_OWNER_ROLE) {
        LaunchpadTypes.ProjectInfo storage _projectInfo = projects[_projectId];
        require(
            hasRole(
                SIGNER_ROLE,
                validateSaleSignature(msg.sender, _amount, _deadline, sig)
            ),
            "Invalid Signer"
        );
        require(
            projectOwnerDetails[_msgSender()].lpToken == address(0),
            "Already Added"
        );
        address wbnb = IPancakeRouter01(_router).WETH();
        uint256 amountA = (_projectInfo.totalAmount *
            _projectInfo.liqudityPercent) / 100e18;
        uint256 amountB = (totalRaisedInUSD[_projectId] *
            _projectInfo.liqudityPercent) / 100e18;
        if (!isGtan) {
            if (address(wbnb) != address(_projectInfo.saleDetails.pairToken)) {
                _addLiquidity(
                    _router,
                    _token,
                    _projectInfo.saleDetails.pairToken,
                    amountA,
                    amountB,
                    wbnb,
                    2
                );
                return;
            } else {
                _addLiquidity(
                    _router,
                    _token,
                    _projectInfo.saleDetails.pairToken,
                    amountA,
                    amountB,
                    wbnb,
                    1
                );
                return;
            }
        } else {
            _addLiquidity(
                _router,
                _token,
                _projectInfo.saleDetails.pairToken,
                amountA,
                amountB,
                wbnb,
                0
            );
            return;
        }
    }

    function _addLiquidity(
        address _router,
        address _tokenA,
        address _tokenB,
        uint256 _amountA,
        uint256 _amountB,
        address _wbnb,
        uint8 _flag
    ) internal {
        uint256 bnbPrice = getBNBPriceInUSD();
        projects[_projectId].totalAmount -= _amountA;
        totalRaisedInUSD[_projectId] -= _amountB;
        uint256 bnbAmount = (_amountB * 1e18) / bnbPrice;
        uint256 liquidity;
        if (_flag == 0) {
            address[] memory path = new address[](2);
            path[0] = _wbnb;
            path[1] = _tokenA;
            _amountB = this.getMarketPrice(_router, path, bnbAmount)[1];
            (, , liquidity) = IPancakeRouter01(_router).addLiquidity(
                _tokenA,
                _tokenB,
                _amountA,
                _amountB,
                _amountA,
                _amountB,
                address(this),
                block.timestamp + 60
            );
        } else if (_flag == 1) {
            (, , liquidity) = IPancakeRouter01(_router).addLiquidityETH{
                value: bnbAmount
            }(
                _tokenA,
                _amountA,
                _amountA,
                bnbAmount,
                address(this),
                block.timestamp + 60
            );
        } else {
            (, , liquidity) = IPancakeRouter01(_router).addLiquidity(
                _tokenA,
                _tokenB,
                _amountA,
                _amountB,
                _amountA,
                _amountB,
                address(this),
                block.timestamp + 60
            );
        }
        projectOwnerDetails[_msgSender()].lpTokenOwned = liquidity;
        projectOwnerDetails[_msgSender()].liquidityTimestamp = block.timestamp;
    }

    function contribute(
        address _router,
        address _token,
        uint256 _amount,
        uint256 _deadline,
        bool isGtan,
        LaunchpadTypes.Sig memory sig
    ) external payable {
        LaunchpadTypes.ProjectInfo storage _projectInfo = projects[_projectId];
        require(
            block.timestamp > _projectInfo.saleDetails.startTime &&
                block.timestamp < _projectInfo.saleDetails.endTime,
            "Sale is not active"
        );
        require(
            hasRole(
                SIGNER_ROLE,
                validateSaleSignature(msg.sender, _amount, _deadline, sig)
            ),
            "Sale : Invalid Signer"
        );

        if (_token != address(0)) {
            _contributeToken(_router, _token, _amount, _deadline, isGtan);
        } else {
            _contributeETH(_router, _amount, _deadline);
        }
        updateUserForVesting(msg.sender);
    }

    function _contributeToken(
        address _router,
        address _token,
        uint256 _amount,
        uint256 _deadline,
        bool isGtan
    ) internal {
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        uint256 commision = getCommisionFee(_amount);
        _amount -= commision;

        address wbnb = IPancakeRouter01(_router).WETH();
        if (isGtan) {
            _handleGtanToken(_router, _token, _amount, _deadline, wbnb);
        } else {
            _handleNormalToken(_router, _token, _amount, _deadline, wbnb);
        }
    }

    function _contributeETH(
        address _router,
        uint256 _amount,
        uint256 _deadline
    ) internal {
        require(msg.value == _amount, "Invalid ETH Value");
        require(_deadline > block.timestamp, "Invalid Deadline");
        uint256 commisionFee = getCommisionFee(_amount);
        _amount -= commisionFee;
        uint256 bnbPrice = getBNBPriceInUSD();
        uint256 contributionInUSD = (_amount * bnbPrice) / 1e18;
        convertUsdPrice(msg.sender, address(0), contributionInUSD);

        address wbnb = IPancakeRouter01(_router).WETH();
        if (
            address(wbnb) != address(projects[_projectId].saleDetails.pairToken)
        ) {
            address[] memory path = new address[](2);
            path[0] = address(wbnb);
            path[1] = projects[_projectId].saleDetails.pairToken;
            uint256[] memory amounts = this.getMarketPrice(
                _router,
                path,
                _amount
            );
            IPancakeRouter01(_router).swapExactETHForTokens{value: _amount}(
                amounts[amounts.length - 1],
                path,
                address(this),
                _deadline
            );
        }
    }

    function _handleGtanToken(
        address _router,
        address _token,
        uint256 _amount,
        uint256 _deadline,
        address wbnb
    ) internal {
        address[] memory path = new address[](2);
        path[0] = _token;
        path[1] = wbnb;
        _amount = this.getMarketPrice(_router, path, _amount)[1];
        uint256 bnbPrice = getBNBPriceInUSD();
        uint256 contributionInUSD = (_amount * bnbPrice) / 1e18;
        convertUsdPrice(msg.sender, _token, contributionInUSD);

        if (
            address(_token) ==
            address(projects[_projectId].saleDetails.pairToken)
        ) {
            return;
        } else if (
            address(wbnb) != address(projects[_projectId].saleDetails.pairToken)
        ) {
            address[] memory _path = new address[](3);
            _path[0] = _token;
            _path[1] = wbnb;
            _path[2] = address(projects[_projectId].saleDetails.pairToken);
            uint256[] memory amounts = this.getMarketPrice(
                _router,
                _path,
                _amount
            );
            IERC20(_token).safeIncreaseAllowance(_router, _amount);
            IPancakeRouter01(_router).swapExactTokensForTokens(
                _amount,
                amounts[amounts.length - 1],
                _path,
                address(this),
                _deadline
            );
        } else {
            IERC20(_token).safeIncreaseAllowance(_router, _amount);
            IPancakeRouter01(_router).swapExactTokensForETH(
                _amount,
                0,
                path,
                address(this),
                _deadline
            );
        }
    }

    function _handleNormalToken(
        address _router,
        address _token,
        uint256 _amount,
        uint256 _deadline,
        address wbnb
    ) internal {
        convertUsdPrice(msg.sender, _token, _amount);
        if (
            address(_token) ==
            address(projects[_projectId].saleDetails.pairToken)
        ) {
            return;
        } else if (
            address(wbnb) != address(projects[_projectId].saleDetails.pairToken)
        ) {
            address[] memory _path = new address[](3);
            _path[0] = _token;
            _path[1] = wbnb;
            _path[2] = address(projects[_projectId].saleDetails.pairToken);
            uint256[] memory amounts = this.getMarketPrice(
                _router,
                _path,
                _amount
            );
            IERC20(_token).safeIncreaseAllowance(_router, _amount);
            IPancakeRouter01(_router).swapExactTokensForTokens(
                _amount,
                amounts[amounts.length - 1],
                _path,
                address(this),
                _deadline
            );
            return;
        } else {
            address[] memory path = new address[](2);
            path[0] = _token;
            path[1] = address(projects[_projectId].saleDetails.pairToken);

            IERC20(_token).safeIncreaseAllowance(_router, _amount);
            IPancakeRouter01(_router).swapExactTokensForETH(
                _amount,
                0,
                path,
                address(this),
                _deadline
            );
            return;
        }
    }

    function convertUsdPrice(
        address _user,
        address _token,
        uint256 _amount
    ) internal {
        investorInfo[_projectId][_user].investedAsset.push(_token);
        investorInfo[_projectId][_user].lastClaimTimestamp = block.timestamp;
        if (
            _amount < presaleDetails[_projectId].minContribution ||
            _amount > presaleDetails[_projectId].maxContribution
        ) revert MinMaxCollapse();
        totalRaisedInUSD[_projectId] += _amount;
        investorInfo[_projectId][_user].investedAmount.push(_amount);
        return;
    }

    function getMarketPrice(
        address _router,
        address[] memory path,
        uint256 amountIn
    ) external view returns (uint256[] memory amounts) {
        amounts = IPancakeRouter01(_router).getAmountsOut(amountIn, path);
    }

    function proceedClaim(
        address _user,
        uint256 _amount,
        bool isVesting
    ) private {
        LaunchpadTypes.ProjectInfo storage project = projects[_projectId];
        LaunchpadTypes.UserDetails storage userInfo = investorInfo[_projectId][
            msg.sender
        ];
        require(block.timestamp > project.saleDetails.endTime, "Sale Not End");
        require(userInfo.investedAmount.length > 0, "Not Contributed");

        uint256 userRewardAmount = this.calcReward(_user);
        if (!isVesting) {
            require(
                project.claimTypeDetail.claimType ==
                    LaunchpadTypes.ClaimType.NormalClaim,
                "Not Vesting Claim"
            );
            require(_amount <= userRewardAmount, "Amount Exceeds Reward");
            require(
                userInfo.claimedAmount + _amount <= userRewardAmount &&
                    !(userInfo.claimed),
                "Already Claimed"
            );
            userInfo.claimedAmount += _amount;
            if (userInfo.claimedAmount >= userRewardAmount)
                userInfo.claimed = true;
            IERC20(project.saleDetails.token).safeTransfer(_user, _amount);

            return;
        }
        require(
            project.claimTypeDetail.claimType ==
                LaunchpadTypes.ClaimType.VestingClaim,
            "Only Vesting Claim"
        );

        uint256 elapsed = getElapsed(
            userInfo.lastClaimTimestamp,
            userInfo.vestingInterval
        );
        require(elapsed >= 1, "No rewards Available Yet");
        uint256 vestAmount = calcVest(
            userRewardAmount,
            elapsed,
            project.claimTypeDetail.vestRate
        );
        userInfo.claimedAmount += vestAmount;
        require(
            userInfo.claimedAmount <= userRewardAmount || !(userInfo.claimed),
            "Already Claimed"
        );
        if (userInfo.claimedAmount >= userRewardAmount) userInfo.claimed = true;
        IERC20(project.saleDetails.token).safeTransfer(_user, vestAmount);
        updateUserForVesting(_user);
    }

    function refund(address _token,address _user , uint256 _amount , uint256 _deadline ,LaunchpadTypes.Sig memory sig) external {
        require(
            hasRole(
                SIGNER_ROLE,
                validateSaleSignature(_user, _amount, _deadline, sig)
            ),
            "Sale : Invalid Signer"
        );
        require(_user == msg.sender , "Invalid User");
        if (_token == address(0)) {
            payable(_user).transfer(_amount);
        }else{
            IERC20(_token).safeTransfer(_user , _amount);
        }
    }

    function burn() onlyRole(PROJECT_OWNER_ROLE) public  {
        if (projects[_projectId].refundOption == LaunchpadTypes.RefundOption.Burn) {
            uint256 allocatedForSale = projects[_projectId].saleDetails.allocationForSale;
            IERC20(projects[_projectId].saleDetails.token).safeTransfer(0x000000000000000000000000000000000000dEaD , allocatedForSale);
        }

    }

    function calcReward(address _user) external view returns (uint256) {
        uint256 _userFund = this.getUserFund(_user);
        uint8 tokenDecimals = IERC20Metadata(
            projects[_projectId].saleDetails.token
        ).decimals();

        if (
            projects[_projectId].saleDetails.saleType ==
            LaunchpadTypes.SaleType.presale
        ) {
            return ((_userFund * 10**tokenDecimals) /
                presaleDetails[_projectId].tokenPriceinUSD);
        } else {
            uint256 price = ((totalRaisedInUSD[_projectId] * 1e18) /
                projects[_projectId].saleDetails.allocationForSale);

            return ((_userFund * 10**tokenDecimals) / price);
        }
    }

    function getUserFund(address user)
        external
        view
        returns (uint256 depositedFund)
    {
        for (
            uint256 fund;
            fund < investorInfo[_projectId][user].investedAmount.length;
            fund++
        ) {
            depositedFund += investorInfo[_projectId][user].investedAmount[
                fund
            ];
        }
        return depositedFund;
    }

    function calcVest(
        uint256 _amount,
        uint256 elapsed,
        uint256 rate
    ) internal pure returns (uint256) {
        return (_amount * elapsed * rate) / 100e18;
    }

    function getElapsed(uint256 lastTimestamp, uint256 vestInterval)
        internal
        view
        returns (uint256)
    {
        return ((block.timestamp - lastTimestamp) / vestInterval);
    }

    function getCommisionFee(uint256 _amount) internal view returns (uint256) {
        uint256 commisionFee = platformFee[_projectId].commisonFee;
        return ((_amount * commisionFee) / 100e18);
    }

    function updateUserForVesting(address user) internal {
        if (
            projects[_projectId].claimTypeDetail.claimType ==
            LaunchpadTypes.ClaimType.VestingClaim
        ) {
            investorInfo[_projectId][user].lastClaimTimestamp = block.timestamp;
            investorInfo[_projectId][user].vestingInterval = projects[
                _projectId
            ].claimTypeDetail.vestingInterval;
            return;
        }
        return;
    }

    function getBNBPriceInUSD() public view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        // price has 8 decimals → convert to 18 decimals
        return uint256(price) * 1e10;
    }

    function mixHash(
        address _user,
        uint256 _amount,
        uint256 deadline
    ) external view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    _user,
                    _amount,
                    deadline,
                    _projectId,
                    address(this)
                )
            );
    }

    function validateSaleSignature(
        address _user,
        uint256 _amount,
        uint256 deadline,
        LaunchpadTypes.Sig memory sig
    ) public view returns (address) {
        require(
            completed[this.mixHash(_user, _amount, deadline)] != true,
            "Signature exist"
        );
        if (sig.v == 0 && sig.r == bytes32(0x0) && sig.s == bytes32(0x0)) {
            revert("Incorrect bid signature");
        } else {
            return
                this.mixHash(_user, _amount, deadline).recover(
                    sig.v,
                    sig.r,
                    sig.s
                );
        }
    }

    function projectId() external view returns (uint256) {
        return _projectId;
    }
}

contract GiantpadFactory is AccessControl, Pausable, ILaunchpadError {
    using BytesLibrary for bytes32;
    using SafeERC20 for IERC20;

    uint256 public projectId;
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");
    address[] private _projectOwners;
    mapping(address => address[]) private _factory;
    mapping(address => bool) private isTokenExists;
    mapping(bytes32 => bool) public completed; // 1.completed
    address[] public allLaunchpadContract;

    event SaleCreated(
        address indexed projectOwner,
        uint256 indexed projectId,
        address projectToken,
        uint256 tokenAllocation,
        uint256 commisionFee,
        uint256 timestamp
    );

    constructor(address admin, address signer) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SIGNER_ROLE, signer);
    }

    function createSale(
        LaunchpadTypes.ProjectInfo memory _projectInfo,
        LaunchpadTypes.LaunchRules memory _launchRules,
        LaunchpadTypes.PlatformFee memory _platformFee,
        address _commisionAsset,
        uint256 _commisionFee,
        uint256 liquidityLockDuriation,
        LaunchpadTypes.Sig memory sig
    ) external payable whenNotPaused {
        projectId++;
        if (!isAnyExceptionOccurs(_projectInfo, _launchRules, _platformFee))
            return;
        require(
            hasRole(SIGNER_ROLE, validateSaleSignatureView(_projectInfo, sig)),
            "Factory : Invalid Signer"
        );
        bytes memory bytecode = type(GiantSale).creationCode;
        bytes memory arguments = abi.encode(
            _projectInfo,
            _launchRules,
            _platformFee,
            projectId,
            liquidityLockDuriation
        );
        bytes memory deploymentData = abi.encodePacked(bytecode, arguments);

        address saleContract = Create2.deploy(
            0,
            keccak256(
                abi.encodePacked(_factory[msg.sender].length, msg.sender)
            ),
            deploymentData
        );
        require(saleContract != address(0), "Deployment failed");

        if (_commisionAsset == address(0)) {
            require(_commisionFee == msg.value, "invalid Commision Fee");
            payable(saleContract).transfer(_commisionFee);
        } else {
            IERC20(_commisionAsset).safeTransferFrom(
                msg.sender,
                saleContract,
                _commisionFee
            );
        }

        IERC20(_projectInfo.saleDetails.token).safeTransferFrom(
            msg.sender,
            saleContract,
            _projectInfo.totalAmount
        );
        if (_factory[msg.sender].length == 0) _projectOwners.push(msg.sender);
        _factory[msg.sender].push(saleContract);
        isTokenExists[_projectInfo.saleDetails.token] = true;
        emit SaleCreated(
            _projectInfo.owner,
            projectId,
            address(_projectInfo.saleDetails.token),
            _projectInfo.saleDetails.allocationForSale,
            _commisionFee,
            block.timestamp
        );
    }

    function isAnyExceptionOccurs(
        LaunchpadTypes.ProjectInfo memory _projectInfo,
        LaunchpadTypes.LaunchRules memory _launchRules,
        LaunchpadTypes.PlatformFee memory _platformFee
    ) internal view returns (bool) {
        //Checking Sale Type that isn't INVALID OPTION
        if (
            _projectInfo.saleDetails.saleType !=
            LaunchpadTypes.SaleType.fairLaunch &&
            _projectInfo.saleDetails.saleType != LaunchpadTypes.SaleType.presale
        ) revert InvalidOption();

        //Checking Owner Address that isn't ZERO ADDRESS
        if (
            address(_projectInfo.owner) == address(0) ||
            address(_projectInfo.saleDetails.token) == address(0) ||
            address(_projectInfo.saleDetails.pairToken) == address(0)
        ) revert NotZeroValue();

        if (msg.sender != _projectInfo.owner) revert("Invalid Owner");

        //Checking  Sale Start And End that isn't ZERO Value
        if (
            _projectInfo.saleDetails.endTime <= 0 ||
            _projectInfo.saleDetails.startTime <= 0 ||
            block.timestamp > _projectInfo.saleDetails.endTime ||
            _projectInfo.saleDetails.startTime >
            _projectInfo.saleDetails.endTime
        ) revert("Invalid Sale time");

        //CHECKING PLATFORM FEE IS ENABLED OR DISABLED
        if (
            _platformFee.commisonFee <= 0 ||
            _platformFee.projectPlatformFee <= 0 ||
            _platformFee.platformOwner == address(0) ||
            _platformFee.platformSigner == address(0)
        ) revert NotZeroValue();

        //Checking Refund Option that isn't INVALID OPTION
        if (
            _projectInfo.refundOption != LaunchpadTypes.RefundOption.Burn &&
            _projectInfo.refundOption !=
            LaunchpadTypes.RefundOption.ReturnToOwner
        ) revert InvalidOption();
        //Checking Allocation Amount For Sale that isn't ZERO Value
        if (_projectInfo.saleDetails.allocationForSale <= 0)
            revert NotZeroValue();

        if (
            _projectInfo.liqudityPercent <= 0 ||
            _projectInfo.totalAmount <= 0 ||
            _projectInfo.totalAmount <
            _projectInfo.saleDetails.allocationForSale
        ) revert InvalidAmount();

        uint256 liquidityAmount = (_projectInfo.saleDetails.allocationForSale *
            _projectInfo.liqudityPercent) / 100e18;

        require(
            liquidityAmount + _projectInfo.saleDetails.allocationForSale ==
                _projectInfo.totalAmount,
            "Amount Mismatches"
        );

        if (
            _projectInfo.claimTypeDetail.claimType !=
            LaunchpadTypes.ClaimType.VestingClaim &&
            _projectInfo.claimTypeDetail.claimType !=
            LaunchpadTypes.ClaimType.NormalClaim
        ) revert InvalidOption();

        if (
            _projectInfo.claimTypeDetail.claimType ==
            LaunchpadTypes.ClaimType.VestingClaim
        ) {
            if (
                _projectInfo.claimTypeDetail.vestRate <= 0 ||
                _projectInfo.claimTypeDetail.vestingInterval <= 0
            ) revert("Invalid Vesting Interval");
        }

        if (isTokenExists[_projectInfo.saleDetails.token])
            revert("Already Exists");

        if (
            _projectInfo.saleDetails.saleType == LaunchpadTypes.SaleType.presale
        ) {
            //Checking  Launch Rules that isn't ZERO Value
            if (
                _launchRules.tokenPriceinUSD <= 0 ||
                _launchRules.minContribution <= 0 ||
                _launchRules.maxContribution <= 0 ||
                _launchRules.maxContribution < _launchRules.minContribution
            ) revert NotZeroValue();
            if (
                _projectInfo.saleDetails.hardCap <= 0 ||
                _projectInfo.saleDetails.softCap <= 0 ||
                _projectInfo.saleDetails.hardCap <
                _projectInfo.saleDetails.softCap
            ) revert("Invalid Softcap or Hardcap");
            return true;
        } else {
            if (
                _projectInfo.saleDetails.softCap > 0 ||
                _projectInfo.saleDetails.hardCap > 0 ||
                _launchRules.tokenPriceinUSD > 0
            ) revert("Invalid SoftCap or HardCap");
            return true;
        }
    }

    function mixHash(LaunchpadTypes.ProjectInfo memory _projectInfo)
        external
        pure
        returns (bytes32)
    {
        bytes32 hash = keccak256(
            abi.encodePacked(
                _projectInfo.owner,
                _projectInfo.saleDetails.saleType,
                _projectInfo.saleDetails.token,
                _projectInfo.saleDetails.startTime,
                _projectInfo.saleDetails.endTime,
                _projectInfo.saleDetails.softCap,
                _projectInfo.saleDetails.hardCap,
                _projectInfo.saleDetails.allocationForSale,
                _projectInfo.refundOption,
                _projectInfo.liqudityPercent,
                _projectInfo.totalAmount
            )
        );

        return hash;
    }

    function validateSaleSignatureView(
        LaunchpadTypes.ProjectInfo memory _projectInfo,
        LaunchpadTypes.Sig memory sig
    ) public view returns (address) {
        require(
            completed[this.mixHash(_projectInfo)] != true,
            "Signature exist"
        );
        if (sig.v == 0 && sig.r == bytes32(0x0) && sig.s == bytes32(0x0)) {
            revert("Incorrect bid signature");
        } else {
            return this.mixHash(_projectInfo).recover(sig.v, sig.r, sig.s);
        }
    }

    function getCreatedAddress(address account, uint256 index)
        external
        view
        returns (address)
    {
        return _factory[account][index];
    }

    function getAllCreatedAddress(address account)
        external
        view
        returns (address[] memory)
    {
        return _factory[account];
    }

    function getProjectOwnerByIndex(uint256 index)
        external
        view
        returns (address)
    {
        return _projectOwners[index];
    }

    function getProjectOwnersCount() external view returns (uint256) {
        return _projectOwners.length;
    }

    function getCreatedCount(address account) public view returns (uint256) {
        return _factory[account].length;
    }

    function isTokenAlreadyExists(address _token) external view returns (bool) {
        return isTokenExists[_token];
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unPause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
