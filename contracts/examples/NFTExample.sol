// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ConfidentialERC721} from "../token/ERC721/ConfidentialERC721.sol";
import {ConfidentialERC721URIStorage} from "../token/ERC721/ConfidentialERC721URIStorage.sol";
import "../lib/MpcCore.sol";

contract NFTExample is
    ConfidentialERC721,
    Ownable,
    ConfidentialERC721URIStorage
{
    event Minted(address indexed to, uint256 indexed tokenId);

    uint256 private _totalSupply;

    constructor() ConfidentialERC721("Example", "EXL") Ownable(msg.sender) {
        _totalSupply = 0;
        mint(msg.sender);
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
        ctUint64[] calldata _itTokenURI,
        bytes[] calldata _itSignature
    ) public {
        _requireOwned(tokenId);
        address owner = _ownerOf(tokenId);
        if (msg.sender != owner) {
            revert ERC721IncorrectOwner(msg.sender, tokenId, owner);
        }

        gtUint64[] memory _tokenURI = new gtUint64[](_itTokenURI.length);

        itUint64 memory it;

        for (uint256 i = 0; i < _itTokenURI.length; ++i) {
            it.ciphertext = _itTokenURI[i];
            it.signature = _itSignature[i];

            _tokenURI[i] = MpcCore.validateCiphertext(it);
        }

        _setTokenURI(owner, tokenId, _tokenURI);
    }

    function mint(address to) public onlyOwner {
        uint256 tokenId = _totalSupply;
        _mint(to, tokenId); // at this stage, token URI is null and can leak some information
        _totalSupply += 1;

        emit Minted(to, tokenId);
    }

    function _mint(
        address to,
        uint256 tokenId
    )
        internal
        virtual
        override(ConfidentialERC721, ConfidentialERC721URIStorage)
    {
        return ConfidentialERC721URIStorage._mint(to, tokenId);
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
