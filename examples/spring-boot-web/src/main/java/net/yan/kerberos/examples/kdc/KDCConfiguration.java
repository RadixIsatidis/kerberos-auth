package net.yan.kerberos.examples.kdc;

import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.core.session.SessionKeyProvider;
import net.yan.kerberos.examples.config.KerberosSettingsProperties;
import net.yan.kerberos.examples.config.SessionSettingsProperties;
import net.yan.kerberos.kdc.as.AuthenticationService;
import net.yan.kerberos.kdc.tgc.AuthenticatorVerifyProvider;
import net.yan.kerberos.kdc.tgc.TicketGrantingService;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author yanle
 */
@Configuration
@EnableConfigurationProperties({SessionSettingsProperties.class, KerberosSettingsProperties.class})
public class KDCConfiguration {

    @Bean
    public SessionKeyProvider sessionKeyProvider(
            SessionSettingsProperties sessionSettingsProperties
    ) {
        return SessionKeyProvider.factory(sessionSettingsProperties);
    }

    @Bean(name = "kdcAuthenticatorVerifyProvider")
    public AuthenticatorVerifyProvider authenticatorVerifyProvider() {
        return (a, b) -> true;
    }

    @Bean
    public AuthenticationService authenticationService(
            UserDetailsService userDetailsService,
            SessionKeyProvider sessionKeyProvider,
            KerberosSettingsProperties kerberosSettingsProperties,
            CipherProvider cipherProvider
    ) {
        AuthenticationService authenticationService = new AuthenticationService();
        authenticationService.setUserDetailsService(userDetailsService);
        authenticationService.setSessionKeyProvider(sessionKeyProvider);
        authenticationService.setKerberosSettings(kerberosSettingsProperties);
        authenticationService.setCipherProvider(cipherProvider);

        return authenticationService;
    }

    @Bean
    public TicketGrantingService ticketGrantingService(
            UserDetailsService userDetailsService,
            SessionKeyProvider sessionKeyProvider,
            KerberosSettingsProperties kerberosSettingsProperties,
            CipherProvider cipherProvider,
            @Qualifier("kdcAuthenticatorVerifyProvider") AuthenticatorVerifyProvider authenticatorVerifyProvider
    ) {
        TicketGrantingService service = new TicketGrantingService();
        service.setUserDetailsService(userDetailsService);
        service.setSessionKeyProvider(sessionKeyProvider);
        service.setKerberosSettings(kerberosSettingsProperties);
        service.setCipherProvider(cipherProvider);
        service.setAuthenticatorVerifyProvider(authenticatorVerifyProvider);
        return service;
    }
}
