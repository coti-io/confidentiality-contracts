// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {PrivateERC721} from "./token/ERC721/PrivateERC721.sol";
import {PrivateERC721URIStorage} from "./token/ERC721/PrivateERC721URIStorage.sol";
import "./lib/MpcCore.sol";

contract NFTExample is PrivateERC721, PrivateERC721URIStorage {
    constructor() PrivateERC721("Example", "EXL") {}

    function supportsInterface(bytes4 interfaceId) public view virtual override(PrivateERC721, PrivateERC721URIStorage) returns (bool) {
        return interfaceId == type(PrivateERC721URIStorage).interfaceId || super.supportsInterface(interfaceId);
    }

    function setTokenURI(uint256 tokenId, ctUint64 _itTokenURI, bytes calldata _itSignature) public {
        _requireOwned(tokenId);
        
        itUint64 memory it;
        it.ciphertext = _itTokenURI;
        it.signature = _itSignature;

        _setTokenURI(tokenId, MpcCore.validateCiphertext(it));
    }

    function _update(address to, uint256 tokenId, address auth) internal virtual override(PrivateERC721, PrivateERC721URIStorage) returns (address) {
        return PrivateERC721URIStorage._update(to, tokenId, auth);
    }
}