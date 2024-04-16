// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {ConfidentialERC721} from "./ConfidentialERC721.sol";
import "../../lib/MpcCore.sol";

/**
 * @dev ConfidentialERC721 token with storage based token URI management.
 */
abstract contract ConfidentialERC721URIStorage is IERC165, ConfidentialERC721 {
    event MetadataUpdate(uint256 _tokenId);
    event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);

    mapping(uint256 tokenId => utUint64) private _tokenURIs;

    /**
     * @dev See {IERC165-supportsInterface}
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ConfidentialERC721, IERC165) returns (bool) {
        return interfaceId == type(ConfidentialERC721).interfaceId;
    }

    function tokenURI(uint256 tokenId) public view virtual returns (ctUint64) {
        return _tokenURIs[tokenId].userCiphertext;
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Emits {MetadataUpdate}.
     */
    function _setTokenURI(
        address to,
        uint256 tokenId,
        gtUint64 _tokenURI
    ) internal virtual {
        _tokenURIs[tokenId] = MpcCore.offBoardCombined(_tokenURI, to);
        emit MetadataUpdate(tokenId);
    }

    function _mint(address to, uint256 tokenId) internal virtual override {
        ConfidentialERC721._mint(to, tokenId);

        _tokenURIs[tokenId] = MpcCore.offBoardCombined(
            MpcCore.setPublic64(0),
            to
        );
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        // reencrypt with the new user key
        _tokenURIs[tokenId] = MpcCore.offBoardCombined(
            MpcCore.onBoard(_tokenURIs[tokenId].ciphertext),
            to
        );

        return ConfidentialERC721._update(to, tokenId, auth);
    }
}
