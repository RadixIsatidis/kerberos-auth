package net.yan.kerberos.examples.server;

import net.yan.kerberos.client.CacheProvider;
import net.yan.kerberos.client.ServerHelper;
import net.yan.kerberos.client.ServerHelperImpl;
import net.yan.kerberos.client.as.AuthenticationClient;
import net.yan.kerberos.client.cs.AuthenticatorVerifyProvider;
import net.yan.kerberos.client.cs.ClientServerExchangeServer;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.examples.config.SessionSettingsProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * @author yanle
 */
@Configuration
@EnableConfigurationProperties({SessionSettingsProperties.class, ServerProperties.class})
public class ServerConfiguration {


    @SuppressWarnings("Duplicates")
    @Bean(name = "serverAuthenticationClient")
    public AuthenticationClient authenticationClient(
            ServerProperties serverProperties,
            CipherProvider cipherProvider,
            AuthenticationDao authenticationDao
    ) {
        AuthenticationClient client = new AuthenticationClient();
        client.setClientSettings(serverProperties);
        client.setCipherProvider(cipherProvider);
        client.setAuthenticationServiceRequestSupplier(authenticationDao::createRequest);
        client.setAuthenticationServiceRequestFunction(authenticationDao::resolveAuthenticationRequest);
        return client;
    }

    @Bean(name = "serverAuthenticatorVerifyProvider")
    public AuthenticatorVerifyProvider authenticatorVerifyProvider() {
        return (a, b) -> true;
    }

    @Bean
    public ClientServerExchangeServer clientServerExchangeServer(
            CipherProvider cipherProvider,
            AuthenticationDao authenticationDao,
            @Qualifier("serverAuthenticatorVerifyProvider") AuthenticatorVerifyProvider authenticatorVerifyProvider
    ) {
        ClientServerExchangeServer server = new ClientServerExchangeServer();
        server.setCipherProvider(cipherProvider);
        server.setAuthenticatorSupplier(authenticationDao::createAuthenticator);
        server.setClientAuthenticatorVerifier(authenticatorVerifyProvider);
        return server;
    }

    @Bean
    public ServerHelper serverHelper(
            ServerProperties serverProperties,
            @Qualifier("serverAuthenticationClient") AuthenticationClient authenticationClient,
            ClientServerExchangeServer clientServerExchangeServer
    ) {
        ServerHelperImpl helper = new ServerHelperImpl();
        helper.setClientSettings(serverProperties);
        helper.setAuthenticationClient(authenticationClient);
        helper.setClientServerExchangeServer(clientServerExchangeServer);
        helper.setCache(new CacheProvider() {
            private Map<String, String> _map = new HashMap<>();

            @Override
            public String cache(String key, String data) {
                _map.put(key, data);
                return data;
            }

            @Override
            public String get(String key) {
                return _map.get(key);
            }
        });

        return helper;
    }
}
