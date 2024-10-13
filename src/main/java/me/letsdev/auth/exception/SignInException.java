package me.letsdev.auth.exception;

import letsdev.common.exception.support.CustomException;
import letsdev.common.exception.support.ErrorCode;

public class SignInException extends CustomException {
    public SignInException() {
        super();
    }

    public SignInException(String message) {
        super(message);
    }

    public SignInException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignInException(ErrorCode errorCode) {
        super(errorCode);
    }

    public SignInException(ErrorCode errorCode, Throwable cause) {
        super(errorCode, cause);
    }
}
