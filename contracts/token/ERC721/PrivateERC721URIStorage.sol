// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {PrivateERC721} from "./PrivateERC721.sol";
import "../../lib/MpcCore.sol";

/**
 * @dev PrivateERC721 token with storage based token URI management.
 */
abstract contract PrivateERC721URIStorage is IERC165, PrivateERC721 {

    event MetadataUpdate(uint256 _tokenId);
    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);

    mapping(uint256 tokenId => utUint64) private _tokenURIs;

    /**
     * @dev See {IERC165-supportsInterface}
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(PrivateERC721, IERC165) returns (bool) {
        return interfaceId == type(PrivateERC721).interfaceId;
    }

    function tokenURI(uint256 tokenId) public view virtual returns (ctUint64) {
        _requireOwned(tokenId);

        return _tokenURIs[tokenId].userCiphertext;
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Emits {MetadataUpdate}.
     */
    function _setTokenURI(uint256 tokenId, gtUint64 _tokenURI) internal virtual {
        _tokenURIs[tokenId] = MpcCore.offBoardCombined(_tokenURI, msg.sender);
        emit MetadataUpdate(tokenId);
    }

    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address) {
        // reencrypt with the new user key
        _tokenURIs[tokenId] = MpcCore.offBoardCombined(MpcCore.onBoard(_tokenURIs[tokenId].ciphertext), msg.sender);

        return PrivateERC721._update(to, tokenId, auth);
    }
}
