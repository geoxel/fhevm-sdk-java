package org.web3j;

import java.util.List;

public final class FhevmEncryptedValues {
    private final List<String> _handles;
    private final String _inputProof;

    public FhevmEncryptedValues(List<String> handles, String inputProof) {
        _handles = handles;
        _inputProof = inputProof;
    }

    public List<String> getHandles() {
        return _handles;
    }

    public String getInputProof() {
        return _inputProof;
    }
}
