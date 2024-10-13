package me.letsdev.auth.redis;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

@RedisHash("refresh-token")
@Getter
@Builder
public class RefreshToken {
    @Id
    private String refreshToken;
    @Indexed
    private String username;
    // ... userAgent, 마지막 접속 아이피, 마지막 접속 국가, ...
    @TimeToLive
    private int timeToLive;
}
