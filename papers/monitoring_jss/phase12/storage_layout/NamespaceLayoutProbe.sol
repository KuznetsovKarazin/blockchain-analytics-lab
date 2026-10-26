// SPDX-License-Identifier: MIT
pragma solidity 0.8.7;

import { LibDiamond } from "src/Libraries/LibDiamond.sol";
import { CBridgeFacet } from "src/Facets/CBridgeFacet.sol";

// Compile for storageLayout only. Never deploy this synthetic probe.
contract NamespaceLayoutProbe {
    LibDiamond.DiamondStorage private diamond;
    CBridgeFacet.Storage private cbridge;
    bytes4[9] private selectorPacking;
    address[2] private facetAddressPacking;
}
