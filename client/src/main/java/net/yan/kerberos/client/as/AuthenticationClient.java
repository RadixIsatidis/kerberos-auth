package net.yan.kerberos.client.as;


import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.util.function.Function;
import java.util.function.Supplier;

public class AuthenticationClient {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationClient.class);

    /**
     * Client settings.
     */
    private ClientSettings clientSettings;
    /**
     * Encrypt/Decrypt provider.
     */
    private CipherProvider cipherProvider;

    /**
     * An {@link AuthenticationServiceRequest} supplier, providing the capability of obtaining
     * an {@code AuthenticationServiceRequest} instance.
     */
    private Supplier<AuthenticationServiceRequest> authenticationServiceRequestSupplier;

    /**
     * An {@link AuthenticationServiceRequest} handler, providing the capability of obtaining an encrypted
     * {@link AuthenticationServiceResponse} by using an {@code AuthenticationServiceRequest} instance.
     */
    private Function<AuthenticationServiceRequest, String> authenticationServiceRequestFunction;

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    public CipherProvider getCipherProvider() {
        if (null == cipherProvider)
            cipherProvider = new CipherProvider();
        return cipherProvider;
    }

    public void setCipherProvider(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    /**
     * @param authenticationServiceRequestSupplier An {@link AuthenticationServiceRequest} supplier
     */
    public void setAuthenticationServiceRequestSupplier(Supplier<AuthenticationServiceRequest> authenticationServiceRequestSupplier) {
        this.authenticationServiceRequestSupplier = authenticationServiceRequestSupplier;
    }

    /**
     * @param authenticationServiceRequestFunction An {@link AuthenticationServiceRequest} handler
     */
    public void setAuthenticationServiceRequestFunction(Function<AuthenticationServiceRequest, String> authenticationServiceRequestFunction) {
        this.authenticationServiceRequestFunction = authenticationServiceRequestFunction;
    }

    /**
     * Decrypt response string using client master key..
     *
     * @param string response string
     * @return a {@link AuthenticationServiceResponse} witch containing SK_TGS and TGT_TGS
     * @throws GeneralSecurityException any security exception.
     * @throws ClassNotFoundException   class {@link AuthenticationServiceResponse} not found.
     */
    private AuthenticationServiceResponse decrypt(String string)
            throws GeneralSecurityException, ClassNotFoundException {
        return getCipherProvider().decryptObject(string, getClientSettings().getMasterKey());
    }

    /**
     * Authentication service exchange
     *
     * @return authentication service exchange response
     * @throws KerberosCryptoException any decryption exception.
     * @see #decrypt(String).
     */
    public AuthenticationServiceResponse authenticationServiceExchange() throws KerberosCryptoException {
        if (log.isDebugEnabled())
            log.debug("Start Authentication Service Exchange.");
        AuthenticationServiceRequest request = authenticationServiceRequestSupplier.get();
        if (log.isDebugEnabled())
            log.debug("Get AuthenticationServiceRequest: " + request);
        String responseString = authenticationServiceRequestFunction.apply(request);
        if (log.isDebugEnabled())
            log.debug("Resolve AuthenticationServiceResponse string: " + responseString);
        AuthenticationServiceResponse response;
        try {
            response = decrypt(responseString);
            if (log.isDebugEnabled())
                log.debug("Decrypted AuthenticationServiceResponse: " + response);
        } catch (GeneralSecurityException | ClassNotFoundException e) {
            throw new KerberosCryptoException(e);
        }
        return response;
    }
}
