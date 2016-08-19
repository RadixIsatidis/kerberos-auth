package net.yan.kerberos.client.cs;

import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.core.secure.CipherProvider;
import net.yan.kerberos.data.Authenticator;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rx.Observable;
import rx.exceptions.Exceptions;

import java.security.GeneralSecurityException;
import java.util.function.Function;
import java.util.function.Supplier;

public class ClientServerExchangeClient {

    private static final Logger log = LoggerFactory.getLogger(ClientServerExchangeClient.class);

    /**
     * Encrypt/Decrypt provider.
     */
    private CipherProvider cipherProvider;

    /**
     * An {@link Authenticator} supplier, can obtain an {@code Authenticator} instance.
     */
    private Supplier<Authenticator> authenticatorSupplier;

    /**
     * A {@link ClientServerExchangeRequest} handler, providing the capability of obtaining
     * an {@link ClientServerExchangeResponse} by using an {@code ClientServerExchangeRequest} instance.
     */
    private Function<ClientServerExchangeRequest, ClientServerExchangeResponse> csExchange;

    private AuthenticatorVerifyProvider serverAuthenticatorVerifier;


    public CipherProvider getCipherProvider() {
        if (null == cipherProvider)
            cipherProvider = new CipherProvider();
        return cipherProvider;
    }

    public void setCipherProvider(CipherProvider cipherProvider) {
        this.cipherProvider = cipherProvider;
    }

    public void setAuthenticatorSupplier(Supplier<Authenticator> authenticatorSupplier) {
        this.authenticatorSupplier = authenticatorSupplier;
    }

    public void setCsExchange(Function<ClientServerExchangeRequest, ClientServerExchangeResponse> csExchange) {
        this.csExchange = csExchange;
    }

    public void setServerAuthenticatorVerifier(AuthenticatorVerifyProvider serverAuthenticatorVerifier) {
        this.serverAuthenticatorVerifier = serverAuthenticatorVerifier;
    }

    private Authenticator decrypt(String key, String secret) throws ClassNotFoundException, GeneralSecurityException {
        return getCipherProvider().decryptObject(secret, key);
    }

    /**
     * Decrypt authenticator and verify it.
     * <p>
     * will throw {@link ServerVerifyException} if verify failed (or any verification exception).
     *
     * @param serverName       server name
     * @param serverSessionKey server session key
     * @param secret           encrypted authenticator string.
     * @return {@code true} if verify successful, {@code false} else.
     */
    private Observable<Boolean> mutualAuthentication(
            String serverName,
            String serverSessionKey,
            String secret
    ) {
        return Observable.create((Observable.OnSubscribe<Authenticator>) subscriber -> {
            if (log.isDebugEnabled())
                log.debug("Receive server [" + serverName + "] Authenticator: " + secret);
            Authenticator authenticator;
            try {
                authenticator = decrypt(serverSessionKey, secret);
                if (log.isDebugEnabled())
                    log.debug("Decrypted server Authenticator: " + authenticator);
                subscriber.onNext(authenticator);
                subscriber.onCompleted();
            } catch (ClassNotFoundException | GeneralSecurityException e) {
                subscriber.onError(new ServerVerifyException(e));
            }
        }).map(authenticator -> {
            boolean result = false;
            try {
                result = serverAuthenticatorVerifier.verify(serverName, authenticator);
            } catch (ServerVerifyException e) {
                throw Exceptions.propagate(e);
            }
            if (log.isDebugEnabled())
                log.debug("Verify server authenticator " + result);
            if (!result)
                throw Exceptions.propagate(new ServerVerifyException("Cannot verify server info:" + serverName));
            return true;
        });
    }

    /**
     * Client-Server Exchange.
     *
     * @param serverName       server name.
     * @param serverSessionKey SK_SERVER
     * @param serverTicket     SERVER_TICKET
     * @return SK_SERVER
     */
    public Observable<String> clientServerExchange(
            String serverName,
            String serverSessionKey,
            String serverTicket
    ) {
        return Observable.create((Observable.OnSubscribe<Authenticator>) subscriber -> {
            log.info(String.format("Client Server Exchange: SERVER: [%s], SK_SERVER: [%s], ST: [%s]",
                    serverName, serverSessionKey, serverTicket));
            // 组Authenticator
            Authenticator authenticator = authenticatorSupplier.get();
            if (log.isDebugEnabled())
                log.debug("Create client Authenticator: " + authenticator);
            subscriber.onNext(authenticator);
            subscriber.onCompleted();
        }).map(authenticator -> {
            String encryptedAuth;
            try {
                encryptedAuth = getCipherProvider().encryptObject(authenticator, serverSessionKey);
                if (log.isDebugEnabled())
                    log.debug("Encrypted client authenticator: " + encryptedAuth);
                return encryptedAuth;
            } catch (GeneralSecurityException e) {
                throw Exceptions.propagate(new KerberosCryptoException(e));
            }
        }).map(encryptedAuth -> {
            ClientServerExchangeRequest request = new ClientServerExchangeRequest();
            request.setServerName(serverName);
            request.setServerTicket(serverTicket);
            request.setAuthenticator(encryptedAuth);
            if (log.isDebugEnabled())
                log.debug("Create ClientServerExchangeRequest:" + request);
            return request;
        }).flatMap(request -> {
            ClientServerExchangeResponse response = csExchange.apply(request);
            if (log.isDebugEnabled())
                log.debug("Receive ClientServerExchangeResponse: " + response);
            return mutualAuthentication(serverName, serverSessionKey, response.getAuthenticator());
        }).map(b -> serverSessionKey);
    }
}
