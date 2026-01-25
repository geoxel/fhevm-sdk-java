package org.web3j.fhe;

public final class FheException extends Exception {
    private final int errorCode;

    public FheException(int errorCode) {
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
