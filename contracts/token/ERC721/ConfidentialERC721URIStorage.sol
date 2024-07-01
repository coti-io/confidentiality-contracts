// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ConfidentialERC721} from "./ConfidentialERC721.sol";
import "../../lib/MpcCore.sol";

/**
 * @dev ConfidentialERC721 token with storage based token URI management.
 */
abstract contract ConfidentialERC721URIStorage is IERC165, ConfidentialERC721 {
    mapping(uint256 tokenId => utUint64[]) private _tokenURIs;
    
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
        utUint64[] memory _tokenURI = _tokenURIs[tokenId];

        ctUint64[] memory _userTokenURI = new ctUint64[](_tokenURIs[tokenId].length);

        for (uint256 i = 0; i < _tokenURI.length; ++i) {
            _userTokenURI[i] = _tokenURI[i].userCiphertext;
        }
        
        return _userTokenURI;
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

        _setTokenURI(to, tokenId, _tokenURI, true);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Emits {MetadataUpdate}.
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        gtUint64[] memory _tokenURI,
        bool updateCiphertext
    ) private {
        if (ownerOf(tokenId) == address(0)) {
            revert ERC721URIStorageNonMintedToken(tokenId);
        }

        // we must first make sure that tokenURI has the correct length
        utUint64[] storage tokenURI = _tokenURIs[tokenId];

        utUint64 memory offBoardCombined;

        if (updateCiphertext) {
            for (uint256 i = 0; i < _tokenURI.length; ++i) {
                offBoardCombined = MpcCore.offBoardCombined(_tokenURI[i], to);

                tokenURI.push(offBoardCombined);
            }

            _tokenURIs[tokenId] = tokenURI;
        } else {
            for (uint256 i = 0; i < _tokenURI.length; ++i) {
                offBoardCombined = MpcCore.offBoardCombined(_tokenURI[i], to);

                tokenURI[i].userCiphertext = offBoardCombined.userCiphertext;
            }

            _tokenURIs[tokenId] = tokenURI;
        }
        
        emit MetadataUpdate(tokenId);
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        utUint64[] memory _tokenURI = _tokenURIs[tokenId];

        gtUint64[] memory _networkTokenURI = new gtUint64[](_tokenURI.length);

        for (uint256 i = 0; i < _networkTokenURI.length; ++i) {
            _networkTokenURI[i] = MpcCore.onBoard(_tokenURI[i].ciphertext);
        }

        // reencrypt with the new user key
         _setTokenURI(to, tokenId, _networkTokenURI, false);

        return ConfidentialERC721._update(to, tokenId, auth);
    }
}
