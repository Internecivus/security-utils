package com.faust.security.exception;

public class WrongPepperMethodException extends SecurityException {
    private static final long serialVersionUID = -6270455768901354688L;

    public WrongPepperMethodException(final String message) {
        super(message);
    }
}
