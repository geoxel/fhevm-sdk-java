package org.web3j;

public final class FhevmSepoliaConfig extends FhevmConfig {
    // cf. https://docs.zama.org/protocol/solidity-guides/smart-contract/configure/contract_addresses

    public String getVerifyingContractAddress() {
        return "0x5D8BD78e2ea6bbE41f26dFe9fdaEAa349e077478";
    }

    public String getVerifyingContractAddressInputVerification() {
        return "0x483b9dE06E4E4C7D35CCf5837A1668487406D955";
    }

    public String getAclContractAddress() {
        return "0xf0Ffdc93b7E186bC2f8CB3dAA75D86d1930A433D";
    }

    public String getKmsContractAddress() {
        return "0xbE0E383937d564D7FF0BC3b46c51f0bF8d5C311A";
    }

    public String getInputVerifierContractAddress() {
        return "0xBBC1fFCdc7C316aAAd72E807D9b0272BE8F84DA0";
    }

    public int getChainId() {
        return 11155111;
    }

    public int getGatewayChainId() {
        return 10901; // (42 << 8) + 149
    }

    public String getRelayerUrl() {
        return "https://relayer.testnet.zama.org";
    }

    public String getInfuraUrl() {
        return "https://sepolia.infura.io/v3";
    }
}
