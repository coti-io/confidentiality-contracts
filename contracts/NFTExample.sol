// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ConfidentialERC721} from "./token/ERC721/ConfidentialERC721.sol";
import {ConfidentialERC721URIStorage} from "./token/ERC721/ConfidentialERC721URIStorage.sol";
import "./lib/MpcCore.sol";

contract NFTExample is ConfidentialERC721, ConfidentialERC721URIStorage {
    event Minted(address indexed to, uint256 indexed tokenId);

    // The next token ID to be minted.
    uint256 private _totalSupply;

    address private _owner;

    constructor() ConfidentialERC721("Example", "EXL") {
        _owner = msg.sender;
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ConfidentialERC721, ConfidentialERC721URIStorage)
        returns (bool)
    {
        return
            interfaceId == type(ConfidentialERC721URIStorage).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function setTokenURI(
        uint256 tokenId,
        ctUint64 _itTokenURI,
        bytes calldata _itSignature
    ) public {
        _requireOwned(tokenId);

        itUint64 memory it;
        it.ciphertext = _itTokenURI;
        it.signature = _itSignature;

        _setTokenURI(tokenId, MpcCore.validateCiphertext(it));
    }

    function mint(address to) public {
        uint256 tokenId = _totalSupply;
        require(to != address(0), "Invalid address");
        require(msg.sender == _owner, "Not owner");
        require(!isMinted(tokenId), "Already minted");
        _safeMint(to, tokenId);

        _totalSupply += 1;

        emit Minted(to, tokenId);
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    )
        internal
        virtual
        override(ConfidentialERC721, ConfidentialERC721URIStorage)
        returns (address)
    {
        return ConfidentialERC721URIStorage._update(to, tokenId, auth);
    }
}
