package me.letsdev.core.jwt.property;

import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import me.letsdev.core.jwt.exception.JwtPropertiesErrorCode;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;

import java.security.Key;
import java.util.Objects;

@ConfigurationProperties("app.jwt")
@ConfigurationPropertiesBinding
public record DemoJwtProperties(
        String secret,
        Long maxAge
) {
    public DemoJwtProperties {
        var SECRET_IS_NULL = JwtPropertiesErrorCode.SECRET_IS_NULL;
        var SECRET_IS_BLANK = JwtPropertiesErrorCode.SECRET_IS_BLANK;
        var MAX_AGE_IS_NON_POSITIVE = JwtPropertiesErrorCode.MAX_AGE_IS_NON_POSITIVE;

        // secret
        try {
            Objects.requireNonNull(secret);
        } catch (NullPointerException npe) {
            throw SECRET_IS_NULL.defaultException(npe);
        }

        if (secret.isBlank()) {
            throw SECRET_IS_BLANK.defaultException();
        }

        // max age
        if (maxAge == null) {
            maxAge = 1_800L;
        }

        if (maxAge <= 0) {
            throw MAX_AGE_IS_NON_POSITIVE.defaultException();
        }
    }

    public Key secretKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
