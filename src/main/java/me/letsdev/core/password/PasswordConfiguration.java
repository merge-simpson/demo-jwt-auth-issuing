package me.letsdev.core.password;

import letsdev.core.password.PasswordEncoderFactory;
import letsdev.core.password.encoder.option.Argon2dPasswordEncoderOption;
import letsdev.core.password.encoder.option.Argon2idPasswordEncoderOption;
import letsdev.core.password.encoder.option.PasswordEncoderOption;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class PasswordConfiguration {
    @Bean
    public PasswordEncoderFactory passwordEncoderFactory() {
        return PasswordEncoderFactory.builder()
                .expireAfterAccess(10, TimeUnit.MINUTES)
                .maximumSize(10)
                .build();
    }

    @Bean
    public PasswordEncoderOption passwordEncoderOption() {
        return Argon2idPasswordEncoderOption.fromDefaultBuilder()
                .gain(3.0f) // gain 조절이 가장 간편하게 강도를 조절할 수 있습니다. (메모리 비용에 비례)
                .build();
    }

    @Bean
    public PasswordEncoderOption refreshTokenEncoderOption() {
        // Refresh token is exactly random created and has short ttl.
        //  So that much encryption cost is not required.
        return Argon2idPasswordEncoderOption.fromDefaultBuilder()
                .gain(0.5f)
                .build();
    }

    @Bean
    public PasswordEncoderOption historyEncoderOption() {
        return Argon2dPasswordEncoderOption.fromDefaultBuilder()
                .gain(3.0f)
                .build();
    }
}
