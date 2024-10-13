package me.letsdev.core.jwt.exception;

import letsdev.common.exception.support.ErrorCode;
import org.springframework.http.HttpStatus;

public enum JwtPropertiesErrorCode implements ErrorCode {
    SECRET_IS_NULL("JWT Secret must not be null.", HttpStatus.INTERNAL_SERVER_ERROR),
    SECRET_IS_BLANK("JWT Secret must not be blank.", HttpStatus.INTERNAL_SERVER_ERROR),
    MAX_AGE_IS_NON_POSITIVE("Max age must be positive.", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String message;
    private final HttpStatus status;

    JwtPropertiesErrorCode(String message, HttpStatus status) {
        this.message = message;
        this.status = status;
    }

    @Override
    public String defaultMessage() {
        return message;
    }

    @Override
    public HttpStatus defaultHttpStatus() {
        return status;
    }

    @Override
    public JwtPropertiesException defaultException() {
        return new JwtPropertiesException(this);
    }

    @Override
    public JwtPropertiesException defaultException(Throwable cause) {
        return new JwtPropertiesException(this, cause);
    }
}
