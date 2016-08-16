package net.yan.kerberos.examples.client;

import net.yan.kerberos.client.ClientHelper;
import net.yan.kerberos.client.ClientHelperImpl;
import net.yan.kerberos.client.as.AuthenticationClient;
import net.yan.kerberos.client.cs.ClientServerExchangeClient;
import net.yan.kerberos.client.tgc.TicketGrantingClient;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.examples.config.SessionSettingsProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author yanle
 */
@Configuration
@EnableConfigurationProperties({SessionSettingsProperties.class, ClientProperties.class})
public class ClientConfiguration {

    @SuppressWarnings("Duplicates")
    @Bean(name = "clientAuthenticationClient")
    public AuthenticationClient authenticationClient(
            ClientProperties clientProperties,
            CipherProvider cipherProvider,
            AuthenticationServerDao authenticationServerDao
    ) {
        AuthenticationClient client = new AuthenticationClient();
        client.setClientSettings(clientProperties);
        client.setCipherProvider(cipherProvider);
        client.setAuthenticationServiceRequestSupplier(authenticationServerDao::createRequest);
        client.setAuthenticationServiceRequestFunction(authenticationServerDao::resolveAuthenticationRequest);
        return client;
    }

    @Bean
    public TicketGrantingClient ticketGrantingClient(
            CipherProvider cipherProvider,
            AuthenticationServerDao authenticationServerDao
    ) {
        TicketGrantingClient client = new TicketGrantingClient();
        client.setCipherProvider(cipherProvider);
        client.setAuthenticatorSupplier(authenticationServerDao::createAuthenticator);
        client.setTicketGrantingServiceRequestFunction(authenticationServerDao::resolveTicketGrantingRequest);
        return client;
    }

    @Bean
    public ClientServerExchangeClient clientServerExchangeClient(
            CipherProvider cipherProvider,
            AuthenticationServerDao authenticationServerDao
    ) {
        ClientServerExchangeClient client = new ClientServerExchangeClient();
        client.setCipherProvider(cipherProvider);
        client.setAuthenticatorSupplier(authenticationServerDao::createAuthenticator);
        client.setCsExchange(authenticationServerDao::resolveClientServerRequest);
        client.setServerAuthenticatorVerifier((a, b) -> true);
        return client;
    }

    @Bean
    public ClientHelper clientHelper(
            ClientProperties clientProperties,
            @Qualifier("clientAuthenticationClient") AuthenticationClient client,
            CipherProvider cipherProvider,
            TicketGrantingClient ticketGrantingClient,
            ClientServerExchangeClient clientServerExchangeClient,
            AuthenticationServerDao authenticationServerDao
    ) {
        ClientHelperImpl clientHelper = new ClientHelperImpl();
        clientHelper.setAuthenticationClient(client);
        clientHelper.setClientSettings(clientProperties);
        clientHelper.setCipherProvider(cipherProvider);
        clientHelper.setTicketGrantingClient(ticketGrantingClient);
        clientHelper.setClientServerExchangeClient(clientServerExchangeClient);
        clientHelper.setServerTicketGrantingTicketFunction(authenticationServerDao::resolveServerTGT);
        return clientHelper;
    }
}
