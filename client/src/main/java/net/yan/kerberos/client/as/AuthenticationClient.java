package net.yan.kerberos.client.as;


import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.core.KerberosException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.GeneralSecurityException;
import java.util.function.Function;
import java.util.function.Supplier;

public class AuthenticationClient {

    private static final Log log = LogFactory.getLog(AuthenticationClient.class);

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

    public void setAuthenticationServiceRequestSupplier(Supplier<AuthenticationServiceRequest> authenticationServiceRequestSupplier) {
        this.authenticationServiceRequestSupplier = authenticationServiceRequestSupplier;
    }

    public void setAuthenticationServiceRequestFunction(Function<AuthenticationServiceRequest, String> authenticationServiceRequestFunction) {
        this.authenticationServiceRequestFunction = authenticationServiceRequestFunction;
    }


    private AuthenticationServiceResponse decrypt(String string)
            throws GeneralSecurityException, ClassNotFoundException {
        return getCipherProvider().decryptObject(string, getClientSettings().getMasterKey());
    }

    /**
     * Authentication service exchange
     *
     * @return authentication service exchange response
     * @throws KerberosException
     */
    public AuthenticationServiceResponse authenticationServiceExchange() throws KerberosException {
        AuthenticationServiceRequest request = authenticationServiceRequestSupplier.get();
        String responseString = authenticationServiceRequestFunction.apply(request);
        AuthenticationServiceResponse response;
        try {
            response = decrypt(responseString);
        } catch (GeneralSecurityException | ClassNotFoundException e) {
            log.error(e.getMessage());
            throw new KerberosException(e);
        }
        return response;
    }
}
