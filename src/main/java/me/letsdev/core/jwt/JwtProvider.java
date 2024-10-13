package me.letsdev.core.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import me.letsdev.core.jwt.property.DemoJwtProperties;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;

@Component
public final class JwtProvider {

    private final Key secretKey;
    private final Long maxAge;

    public JwtProvider(DemoJwtProperties jwtProperties) {
        this.secretKey = jwtProperties.secretKey();
        this.maxAge = jwtProperties.maxAge();
    }

    /**
     * @param subject 인증할 사용자 계정
     * @param payload 그 외 넣을 정보들
     * @return JWT 문자열
     */
    public String generateJwt(String subject, Map<? extends String, ?> payload) {
        Claims claims = Jwts.claims()
                .subject(subject)
                .add(payload)
                .build();

        Date now = new Date();
        Date expirationAt = new Date(now.getTime() + maxAge);

        return Jwts.builder()
                .claims(claims)
                .issuedAt(now)
                .expiration(expirationAt)
                .signWith(secretKey)
                .compact();
    }
}