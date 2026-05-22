package com.faust.security.exception;

public class WrongPepperException extends SecurityException {
    private static final long serialVersionUID = -6606677029644970304L;

    public WrongPepperException(final Throwable cause) {
        super(cause);
    }
}
