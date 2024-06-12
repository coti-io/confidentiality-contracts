// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "./DataPrivacyFramework.sol";
import "./MpcCore.sol";
import "./MpcInterface.sol";

contract OnChainDatabase is DataPrivacyFramework {

    mapping(string => ctUint64) internal database;

    event encryptedValue(address indexed _from, ctUint64 value);
    event value(address indexed _from, uint64 value);

    constructor() DataPrivacyFramework(false, false) {
        gtUint64 gtContractDate = gtUint64.wrap(ExtendedOperations(MPC_PRECOMPILE).
        SetPublic(bytes1(uint8(MpcCore.MPC_TYPE.SUINT64_T)), uint256(block.timestamp)));
        database["contract_date"] = MpcCore.offBoard(gtContractDate);
        gtUint64 gtCotiUsd = MpcCore.setPublic64(5);
        database["coti_usd_price"] = MpcCore.offBoard(gtCotiUsd);
        gtUint64 gtOilUsdPrice = MpcCore.setPublic64(100);
        database["oil_usd_price"] = MpcCore.offBoard(gtOilUsdPrice);

        uint64 _conditionsCount = 0;
        conditions[_conditionsCount] = Condition(_conditionsCount, msg.sender, "op_set_item", true, false, false, 0, 0,
            0, address(0), "");
        _conditionsCount++;
        conditions[_conditionsCount] = Condition(_conditionsCount, msg.sender, "op_get_item", true, false, false, 0, 0,
            0, address(0), "");
    }

    function set_item(string memory name, ctUint64 _itCT, bytes calldata _itSignature) external {
        itUint64 memory it;
        it.ciphertext = _itCT;
        it.signature = _itSignature;
        if (this.isOperationAllowed(msg.sender, "op_set_item")) {
            gtUint64 gtEncryptedValue = MpcCore.validateCiphertext(it);
            ctUint64 ctEncryptedInput = MpcCore.offBoard(gtEncryptedValue);
            database[name] = ctEncryptedInput;
        } else {
            revert("No Permission!");
        }
    }

    function get_item(string memory name) external {
        if (this.isOperationAllowed(msg.sender, "op_get_item")) {
            gtUint64 gtEncryptedValue = MpcCore.onBoard(database[name]);
            ctUint64 ctEncryptedInput = MpcCore.offBoardToUser(gtEncryptedValue, msg.sender);
            emit encryptedValue(msg.sender, ctEncryptedInput);
        } else {
            revert("No Permission!");
        }
    }

    function get_clear_oil_usd_price() external {
        if (this.isOperationAllowed(msg.sender, "op_get_clear_oil_usd_price")) {
            gtUint64 a = MpcCore.onBoard(database["oil_usd_price"]);
            emit value(msg.sender, MpcCore.decrypt(a));
        } else {
            revert("No Permission!");
        }
    }

    function get_clear_coti_usd_price() external {
        if (this.isOperationAllowed(msg.sender, "op_get_clear_coti_usd_price")) {
            gtUint64 a = MpcCore.onBoard(database["coti_usd_price"]);
            emit value(msg.sender, MpcCore.decrypt(a));
        } else {
            revert("No Permission!");
        }
    }

}