package net.yan.kerberos.examples;

import org.springframework.boot.Banner;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * @author yanle
 */
@SpringBootApplication(scanBasePackageClasses = Application.class)
@EnableConfigurationProperties
public class App {

    private static Class<App> applicationClass = App.class;


    public static void main(String[] args) {
        SpringApplicationBuilder builder = new SpringApplicationBuilder();
        builder.bannerMode(Banner.Mode.OFF)
                .sources(applicationClass);
        builder.run(args);
    }
}
