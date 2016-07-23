package net.yan.kerberos.kdc.config;

import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.core.session.SessionKeyProvider;
import net.yan.kerberos.kdc.as.AuthenticationService;
import net.yan.kerberos.kdc.userdetails.UserDetails;
import net.yan.kerberos.kdc.userdetails.UserDetailsService;
import org.junit.Before;

/**
 * Created by yanle on 2016/7/21.
 */
public abstract class DefaultSettingsTest {

    protected UserDetailsService userDetailsService;

    protected SessionKeyProvider sessionKeyProvider;

    protected KerberosSettings kerberosSettings;

    protected CipherProvider cipherProvider;

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
                    .setTicketGrantServerName("localhost")
                    .build();
        }

        if (null == cipherProvider) {
            cipherProvider = new CipherProvider();
        }

        if (null == authenticationService) {
            authenticationService = new AuthenticationService();
            authenticationService.setCipherProvider(cipherProvider);
            authenticationService.setKerberosSettings(kerberosSettings);
            authenticationService.setSessionKeyProvider(sessionKeyProvider);
            authenticationService.setUserDetailsService(userDetailsService);
        }
    }
}
