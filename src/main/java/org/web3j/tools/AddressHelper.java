package org.web3j.tools;

import org.web3j.crypto.Keys;
import org.web3j.crypto.WalletUtils;

public final class AddressHelper {
    // cf. https://docs.ethers.org/v5/api/utils/address/#utils-computeAddress
    // IsAddress("0x8ba1f109551bd432803012645ac136ddd64dba72") = true
    // IsAddress("XE65GB6LDNXYOFTX0NSV3FUWKOWIXAMJK36") = false (for Web3j)
    // IsAddress("I like turtles.") = false
    public static boolean isAddress(String addr) {
        addr = Helpers.ensure0xPrefix(addr);
        return WalletUtils.isValidAddress(addr);
    }

    // cf. https://docs.ethers.org/v5/api/utils/address/#utils-getAddress
    public static String getChecksumAddress(String addr) throws IllegalArgumentException {
        addr = Helpers.ensure0xPrefix(addr);

        // Validate the address
        boolean isValid = WalletUtils.isValidAddress(addr);
        if (!isValid)
            throw new IllegalArgumentException( "invalid address");

        // // Validate checksummed format
        // boolean isChecksumValid = addressUtil.IsChecksumAddress(addr);
        // if (!isChecksumValid)
        // throw new InvalidOperationException("invalid checksum");

        // Convert / normalize to checksum address (like ethers.utils.getAddress)
        String checksumAddress = Keys.toChecksumAddress(addr);

        return checksumAddress;
    }
}
