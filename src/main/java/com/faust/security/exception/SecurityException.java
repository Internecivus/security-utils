package com.faust.security.exception;

public class SecurityException extends Exception {
    private static final long serialVersionUID = -4828155075370628287L;

    public SecurityException() {
    }

    public SecurityException(final String message) {
        super(message);
    }

    public SecurityException(final Throwable cause) {
        super(cause);
    }
}
