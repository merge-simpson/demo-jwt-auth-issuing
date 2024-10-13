package me.letsdev.core.jwt.exception;

import letsdev.common.exception.support.CustomException;
import letsdev.common.exception.support.ErrorCode;

public class JwtPropertiesException extends CustomException {
    public JwtPropertiesException() {
        super();
    }

    public JwtPropertiesException(String message) {
        super(message);
    }

    public JwtPropertiesException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtPropertiesException(ErrorCode errorCode) {
        super(errorCode);
    }

    public JwtPropertiesException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, cause);
    }
}
