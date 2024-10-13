package me.letsdev.auth.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import letsdev.common.log.AdaptiveLogger;
import letsdev.common.log.LogLevel;
import letsdev.core.password.PasswordEncoderFactory;
import letsdev.core.password.encoder.option.PasswordEncoderOption;
import letsdev.core.password.encoder.port.PasswordEncoder;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import me.letsdev.auth.exception.SignInErrorCode;
import me.letsdev.auth.redis.RefreshToken;
import me.letsdev.auth.redis.RefreshTokenRepository;
import me.letsdev.core.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Map;

// NOTE 로직을 파악하기 쉽도록 한 클래스에 모두 작성했습니다만, 실제 구현할 떄는 서비스 클래스 등에 잘 구분하십시오.
@RestController
@Slf4j
public class SignInLoginOnlyApi {
    private static final Encoder BASE64_ENCODER = Base64.getEncoder().withoutPadding();
    private final PasswordEncoderFactory passwordEncoderFactory;
    private final PasswordEncoderOption passwordEncoderOption;
    private final PasswordEncoderOption refreshTokenEncoderOption;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProvider jwtProvider;

    public SignInLoginOnlyApi(
            PasswordEncoderFactory passwordEncoderFactory,
            @Qualifier("passwordEncoderOption")
            PasswordEncoderOption passwordEncoderOption,
            @Qualifier("refreshTokenEncoderOption")
            PasswordEncoderOption refreshTokenEncoderOption,
            RefreshTokenRepository refreshTokenRepository,
            JwtProvider jwtProvider
    ) {
        this.passwordEncoderFactory = passwordEncoderFactory;
        this.passwordEncoderOption = passwordEncoderOption;
        this.refreshTokenEncoderOption = refreshTokenEncoderOption;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProvider = jwtProvider;
    }

    @PostMapping("/sign-in")
    public AuthenticationResponse signIn(
            @RequestBody @Valid AuthenticationRequest body,
            HttpServletResponse response
    ) {
        // 사용할 것들에 대한 선언부 (이해하기 위해서 볼 땐 이런 구간은 스킵해도 됨.)
        User user = findTestUserByUsername_this_is_for_example(body);
        PasswordEncoder passwordEncoder = passwordEncoderFactory.create(passwordEncoderOption);
        PasswordEncoder refreshTokenEncoder = passwordEncoderFactory.create(refreshTokenEncoderOption);
        String username = body.username();
        String rawPassword = body.password();
        String encodedPassword = user.password();

        // 1. 비밀번호 확인 (또는 이 단계에 스프링 시큐리티 Authentication을 사용해도 됨.)
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) { // passes (이번 예시에서는 무조건 패스함.)
            log.debug("비밀번호가 일치하지 않음 (패스워드 인코더 구현 오류)");
            throw SignInErrorCode.USERNAME_OR_PASSWORD_INCORRECT.defaultException();
        }

        // 2. Generate Access Token
        Map<String, String> payload = Map.of("role", "USER");
        String jwtAccessToken = jwtProvider.generateJwt(username, payload);
        logJwtAccessToken(jwtAccessToken, LogLevel.DEBUG);

        // 3. Generate Refresh Token
        String refreshTokenBase64 = secureRandomBase64(16);
        log.debug("Refresh Token (BASE64): {}", refreshTokenBase64);

        // 3-1. 사용자에게는 원문(Base64로만 인코딩) 제공
        Cookie cookie = new Cookie("refresh_token", refreshTokenBase64);
        cookie.setDomain("");
        cookie.setPath("/");
        cookie.setMaxAge(2_592_000);
        cookie.setHttpOnly(true);
        // cookie.setSecure(true); // ** required for production
        response.addCookie(cookie); // set cookie

        // 3-2. DB(redis)에는 단방향 암호화하여 저장 (해시 값 유출 시 특히 민감)
        var encodedRefreshToken = refreshTokenEncoder.encode(refreshTokenBase64);
        RefreshToken refreshToken = RefreshToken.builder()
                .refreshToken(encodedRefreshToken)
                .build();
        refreshTokenRepository.save(refreshToken);

        // body <- Access Token (AT)
        // cookie <- Refresh Token (RT) HttpOnly;
        return AuthenticationResponse.builder()
                .token(jwtAccessToken)
                .build();
    }

    @DeleteMapping("refresh-tokens")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteAllRefreshTokens() {
        // This is just for test. This must not be allowed for production.
        refreshTokenRepository.deleteAll();
    }

    private String secureRandomBase64(int byteLength) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] seed = secureRandom.generateSeed(16);
        secureRandom.setSeed(seed);

        byte[] randomByte = new byte[byteLength];
        secureRandom.nextBytes(randomByte);
        return BASE64_ENCODER.encodeToString(randomByte);
    }

    private User findTestUserByUsername_this_is_for_example(AuthenticationRequest body) {
        var passwordEncoder = passwordEncoderFactory.create(passwordEncoderOption);
        String encodedPassword = passwordEncoder.encode(body.password());
        return new User(body.username(), encodedPassword);
    }

    private void logJwtAccessToken(String jwtAccessToken, LogLevel logLevel) {
        var logger = AdaptiveLogger.getLogger(SignInLoginOnlyApi.class)
                        .with(logLevel);
        logger.log("jwtAccessToken: {}", jwtAccessToken);

        String[] tokenLabels = jwtAccessToken.split("\\.");
        assert tokenLabels.length == 3 : "JWT 액세스 토큰이 올바른 양식이 아님.";
        logger.log(
                "jwtAccessToken Header (decoded): {}",
                new String(Base64.getDecoder().decode(tokenLabels[0]), StandardCharsets.UTF_8)
        );
        logger.log(
                "jwtAccessToken Payload (decoded): {}",
                new String(Base64.getDecoder().decode(tokenLabels[1]), StandardCharsets.UTF_8)
        );
        logger.log("jwtAccessToken Signature: {}", tokenLabels[2]);
    }

    @Builder
    public record AuthenticationRequest(
            @NotBlank(message = "Please enter a username.")
            @Pattern(
                    regexp = "^[A-Za-z0-9]+$",
                    message = ""
            )
            @Size(min = 3, message = "")
            @Size(max = 30, message = "")
            String username,

            @NotBlank(message = "Please enter the password.")
            @Pattern(
                    regexp = "^[A-Za-z\\d~!@#$%^&*?_=\\-+,./:;]+$",
                    message = ""
            )
            @Size(min = 8, message = "")
            @Size(max = 100, message = "")
            String password
    ) {}

    @Builder
    public record AuthenticationResponse(
            @JsonProperty("access_token")
            String token
    ) {}

    private record User(String username, String password) {}
}
