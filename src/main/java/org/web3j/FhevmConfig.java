package org.web3j;

public abstract class FhevmConfig {
    // DECRYPTION_ADDRESS (Gateway chain)
    public abstract String getVerifyingContractAddress();

    // INPUT_VERIFICATION_ADDRESS (Gateway chain)
    public abstract String getVerifyingContractAddressInputVerification();

    // ACL_CONTRACT_ADDRESS (FHEVM Host chain)
    public abstract String getAclContractAddress();

    // KMS_VERIFIER_CONTRACT_ADDRESS (FHEVM Host chain)
    public abstract String getKmsContractAddress();

    // INPUT_VERIFIER_CONTRACT_ADDRESS (FHEVM Host chain)
    public abstract String getInputVerifierContractAddress();

    // FHEVM Host chain id
    public abstract int getChainId();

    // Gateway chain id
    public abstract int getGatewayChainId();

    public abstract String getRelayerUrl();

    public abstract String getInfuraUrl();
}
