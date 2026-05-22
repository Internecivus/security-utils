package com.faust.security.exception;

public class NonMatchingConfigurationException extends SecurityException {
    private static final long serialVersionUID = -582425884371841299L;

    public NonMatchingConfigurationException(final String message) {
        super(message);
    }
}
