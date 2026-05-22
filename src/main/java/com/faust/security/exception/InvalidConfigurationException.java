package com.faust.security.exception;

public class InvalidConfigurationException extends SecurityException {
    private static final long serialVersionUID = -558306748463705133L;

    public InvalidConfigurationException(final Throwable cause) {
        super(cause);
    }
}
