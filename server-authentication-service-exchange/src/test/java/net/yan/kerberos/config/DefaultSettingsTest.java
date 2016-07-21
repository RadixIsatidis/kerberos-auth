package net.yan.kerberos.config;

import net.yan.kerberos.as.AuthenticationService;
import net.yan.kerberos.core.crypto.CryptoProvider;
import net.yan.kerberos.core.session.SessionKeyProvider;
import net.yan.kerberos.userdetails.UserDetails;
import net.yan.kerberos.userdetails.UserDetailsService;
import org.junit.Before;

/**
 * Created by yanle on 2016/7/21.
 */
public abstract class DefaultSettingsTest {

    protected UserDetailsService userDetailsService;

    protected SessionKeyProvider sessionKeyProvider;

    protected KerberosSettings kerberosSettings;

    protected CryptoProvider cryptoProvider;

    protected AuthenticationService authenticationService;

    @Before
    public void setUp() throws Exception {
        if (null == userDetailsService) {
            userDetailsService = username -> new UserDetails() {
                private static final long serialVersionUID = -4751837956123689325L;

                @Override
                public String getPassword() {
                    return "my user password to encrypt user data and anything, wish it long enough.";
                }

                @Override
                public String getUsername() {
                    return username;
                }

                @Override
                public boolean isAccountNonExpired() {
                    return true;
                }

                @Override
                public boolean isAccountNonLocked() {
                    return true;
                }

                @Override
                public boolean isCredentialsNonExpired() {
                    return true;
                }

                @Override
                public boolean isEnabled() {
                    return true;
                }
            };
        }

        if (null == sessionKeyProvider) {
            sessionKeyProvider = SessionKeyProvider.factory();
        }

        if (null == kerberosSettings) {
            kerberosSettings = new KerberosSettingsBuilder()
                    .setMasterKey("My master key to encrypt anything. Wish it long enough.")
                    .setSessionLifeTime(38 * 60 * 1000L)
                    .setTicketGrantServer("localhost")
                    .build();
        }

        if (null == cryptoProvider) {
            cryptoProvider = new CryptoProvider();
        }

        if (null == authenticationService) {
            authenticationService = new AuthenticationService();
            authenticationService.setCryptoProvider(cryptoProvider);
            authenticationService.setKerberosSettings(kerberosSettings);
            authenticationService.setSessionKeyProvider(sessionKeyProvider);
            authenticationService.setUserDetailsService(userDetailsService);
        }
    }
}
