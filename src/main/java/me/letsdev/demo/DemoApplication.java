package me.letsdev.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

// * Autoconfigured bean 주입을 확인하기 위해 패키지 루트를 다르게 사용함.
@SpringBootApplication(scanBasePackages = "me.letsdev")
@ConfigurationPropertiesScan(basePackages = "me.letsdev")
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

}
