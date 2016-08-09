package net.yan.kerberos.examples.kdc;

import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.core.session.SessionKeyProvider;
import net.yan.kerberos.examples.config.KerberosSettingsProperties;
import net.yan.kerberos.examples.config.SessionSettingsProperties;
import net.yan.kerberos.kdc.as.AuthenticationService;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
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

    @Bean
    public CipherProvider cipherProvider() {
        return new CipherProvider();
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
}
