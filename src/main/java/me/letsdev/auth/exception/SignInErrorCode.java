package me.letsdev.auth.exception;

import letsdev.common.exception.support.ErrorCode;
import org.springframework.http.HttpStatus;

public enum SignInErrorCode implements ErrorCode {
    USERNAME_OR_PASSWORD_INCORRECT("아이디 또는 비밀번호가 올바르지 않습니다.", HttpStatus.BAD_REQUEST);

    private final String message;
    private final HttpStatus status;

    SignInErrorCode(String message, HttpStatus status) {
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
    public SignInException defaultException() {
        return new SignInException(this);
    }

    @Override
    public SignInException defaultException(Throwable cause) {
        return new SignInException(this, cause);
    }
}
