// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ConfidentialERC721} from "./ConfidentialERC721.sol";
import "../../lib/MpcCore.sol";

/**
 * @dev ConfidentialERC721 token with storage based token URI management.
 */
abstract contract ConfidentialERC721URIStorage is IERC165, ConfidentialERC721 {
    mapping(uint256 tokenId => utString) private _tokenURIs;
    

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

    function tokenURI(uint256 tokenId) public view virtual returns (ctString memory) {
        // utUint64[] memory _tokenURI = _tokenURIs[tokenId];

        // ctUint64[] memory _userTokenURI = new ctUint64[](_tokenURIs[tokenId].length);

        // for (uint256 i = 0; i < _tokenURI.length; ++i) {
        //     _userTokenURI[i] = _tokenURI[i].userCiphertext;
        // }
        
        return _tokenURIs[tokenId].userCiphertext;
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        itString calldata itTokenURI
    ) internal virtual {
        gtString memory _tokenURI = gtString(new gtUint64[](itTokenURI.ciphertext.value.length));

        itUint64 memory it;

        for (uint256 i = 0; i < itTokenURI.ciphertext.value.length; ++i) {
            it.ciphertext = itTokenURI.ciphertext.value[i];
            it.signature = itTokenURI.signature[i];

            _tokenURI.value[i] = MpcCore.validateCiphertext(it);
        }

        _setTokenURI(to, tokenId, _tokenURI, true);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        gtString memory _tokenURI,
        bool updateCiphertext
    ) private {
        if (ownerOf(tokenId) == address(0)) {
            revert ERC721URIStorageNonMintedToken(tokenId);
        }

        utString memory offBoardCombined = MpcCore.offBoardCombined(_tokenURI, to);

        if (updateCiphertext) {
            _tokenURIs[tokenId] = offBoardCombined;
        } else {
            _tokenURIs[tokenId].userCiphertext = offBoardCombined.userCiphertext;
        }
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        ctString memory _tokenURI = _tokenURIs[tokenId].ciphertext;

        gtString memory _networkTokenURI = gtString(new gtUint64[](_tokenURI.value.length));

        for (uint256 i = 0; i < _networkTokenURI.value.length; ++i) {
            _networkTokenURI.value[i] = MpcCore.onBoard(_tokenURI.value[i]);
        }

        // reencrypt with the new user key
         _setTokenURI(to, tokenId, _networkTokenURI, false);

        return ConfidentialERC721._update(to, tokenId, auth);
    }
}
