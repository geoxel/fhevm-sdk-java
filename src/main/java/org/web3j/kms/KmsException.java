package org.web3j.kms;

public final class KmsException extends Exception {
    private final int errorCode;

    public KmsException(int errorCode) {
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
