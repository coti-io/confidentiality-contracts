// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ConfidentialERC721} from "./ConfidentialERC721.sol";
import "../../lib/MpcCore.sol";

/**
 * @dev ConfidentialERC721 token with storage based token URI management.
 */
abstract contract ConfidentialERC721URIStorage is IERC165, ConfidentialERC721 {
    mapping(uint256 tokenId => ctUint64[]) private _userTokenURIs;

    mapping(uint256 tokenId => ctUint64[]) private _networkTokenURIs;
    
    event MetadataUpdate(uint256 _tokenId);
    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);

    error ERC721URIStorageNonMintedToken(uint256 tokenId);

    /**
     * @dev See {IERC165-supportsInterface}
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ConfidentialERC721, IERC165) returns (bool) {
        return interfaceId == type(ConfidentialERC721).interfaceId;
    }

    function tokenURI(uint256 tokenId) public view virtual returns (ctUint64[] memory) {
        return _userTokenURIs[tokenId];
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Emits {MetadataUpdate}.
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        ctUint64[] calldata _itTokenURI,
        bytes[] calldata _itSignature
    ) internal virtual {
        gtUint64[] memory _tokenURI = new gtUint64[](_itTokenURI.length);

        itUint64 memory it;

        for (uint256 i = 0; i < _itTokenURI.length; ++i) {
            it.ciphertext = _itTokenURI[i];
            it.signature = _itSignature[i];

            _tokenURI[i] = MpcCore.validateCiphertext(it);
        }

        _setTokenURI(to, tokenId, _tokenURI);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Emits {MetadataUpdate}.
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        gtUint64[] memory _tokenURI
    ) private {
        if (!isMinted(tokenId)) {
            revert ERC721URIStorageNonMintedToken(tokenId);
        }

        ctUint64[] memory userTokenURI = new ctUint64[](_tokenURI.length);
        ctUint64[] memory networkTokenURI = new ctUint64[](_tokenURI.length);

        utUint64 memory offBoardCombined;

        for (uint256 i = 0; i < _tokenURI.length; ++i) {
            offBoardCombined = MpcCore.offBoardCombined(_tokenURI[i], to);

            userTokenURI[i] = offBoardCombined.userCiphertext;
            networkTokenURI[i] = offBoardCombined.ciphertext;
        }

        _userTokenURIs[tokenId] = userTokenURI;
        _networkTokenURIs[tokenId] = networkTokenURI;
        
        emit MetadataUpdate(tokenId);
    }

    function _mint(address to, uint256 tokenId) internal virtual override {
        ConfidentialERC721._mint(to, tokenId);

        gtUint64[] memory _tokenURI = new gtUint64[](0);

        _setTokenURI(to, tokenId, _tokenURI);
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        ctUint64[] memory _networkTokenURI = _networkTokenURIs[tokenId];
        uint256 length = _networkTokenURI.length;

        gtUint64[] memory _tokenURI = new gtUint64[](length);

        for (uint256 i = 0; i < length; ++i) {
            _tokenURI[i] = MpcCore.onBoard(_networkTokenURI[i]);
        }

        // reencrypt with the new user key
         _setTokenURI(to, tokenId, _tokenURI);

        return ConfidentialERC721._update(to, tokenId, auth);
    }
}
