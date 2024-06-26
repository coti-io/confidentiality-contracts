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
    uint256 private _totalSupply;
    
    event Minted(address indexed to, uint256 indexed tokenId);

    constructor() ConfidentialERC721("Example", "EXL") Ownable(msg.sender) {}

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

    function mint(
        address to,
        ctUint64[] calldata _itTokenURI,
        bytes[] calldata _itSignature
    ) public onlyOwner {
        uint256 tokenId = _totalSupply;
        _mint(to, tokenId);
        _totalSupply += 1;

        ConfidentialERC721URIStorage._setTokenURI(msg.sender, tokenId, _itTokenURI, _itSignature);

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
