package net.yan.kerberos.examples;

import net.yan.kerberos.core.secure.CipherProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * @author yanle
 */
@Configuration
@ComponentScan(basePackageClasses = Application.class)
public class AppConfiguration {

    public static final int READ_TIME_OUT = 1000000000;

    public static final int CONNECT_TIME_OUT = 1000000000;

    @Bean
    public CipherProvider cipherProvider() {
        return new CipherProvider();
    }

    @Bean
    public ClientHttpRequestFactory getClientHttpRequestFactory() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setReadTimeout(READ_TIME_OUT);
        factory.setConnectTimeout(CONNECT_TIME_OUT);
        return factory;
    }

    @Bean
    public RestTemplate getRestTemplate(
            ClientHttpRequestFactory requestFactory
    ) {
        return new RestTemplate(requestFactory);
    }
}
