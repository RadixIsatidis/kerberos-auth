package net.yan.kerberos.client;

import net.yan.kerberos.client.as.AuthenticationClient;
import net.yan.kerberos.client.core.ClientSettings;
import net.yan.kerberos.client.cs.ClientServerExchangeServer;
import net.yan.kerberos.client.cs.ServerVerifyException;
import net.yan.kerberos.core.KerberosCryptoException;
import net.yan.kerberos.data.AuthenticationServiceResponse;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import rx.Observable;
import rx.exceptions.Exceptions;

import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * A server side helper.
 */
public class ServerHelperImpl implements ServerHelper {

    private static final String TGT_KEY = "$$SERVER-TGT-KEY";

    private static final String SESSION_KEY = "$$SERVER-KDC-SESSION-KEY";

    /**
     * Client settings.
     */
    private ClientSettings clientSettings;

    /**
     * Using to request server-side TGT
     */
    private AuthenticationClient authenticationClient;

    /**
     * Using to authenticate client.
     */
    private ClientServerExchangeServer clientServerExchangeServer;

    /**
     * An TGT_SERVER supplier.
     */
    private Supplier<String> serverTGTSupplier;

    /**
     * Using to cache TGT_SERVER
     */
    private Consumer<String> serverTGTCache;

    /**
     * Using to cache SK_TGS
     */
    private Supplier<String> rootSessionSupplier;

    /**
     * Using to cache SK_TGS
     */
    private Consumer<String> rootSessionCache;

    public ClientSettings getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(ClientSettings clientSettings) {
        this.clientSettings = clientSettings;
    }

    public void setAuthenticationClient(AuthenticationClient authenticationClient) {
        this.authenticationClient = authenticationClient;
    }

    public void setClientServerExchangeServer(ClientServerExchangeServer clientServerExchangeServer) {
        this.clientServerExchangeServer = clientServerExchangeServer;
    }

    public void setCache(CacheProvider cache) {
        serverTGTSupplier = () -> cache.get(TGT_KEY);
        serverTGTCache = (s) -> cache.cache(TGT_KEY, s);
        rootSessionSupplier = () -> cache.get(SESSION_KEY);
        rootSessionCache = (s) -> cache.cache(SESSION_KEY, s);
    }


    /**
     * Get TGT_TGS
     * <p>
     * Will throw {@code KerberosException} if any exception
     *
     * @return TGT
     */
    public Observable<String> getRootSessionKey() {
        Observable<String> fromCache = Observable.create(subscriber -> {
            String rootSessionKey = rootSessionSupplier.get();
            if (null != rootSessionKey)
                subscriber.onNext(rootSessionKey);
            subscriber.onCompleted();
        });

        Observable<String> ASExchange = getRootTicket()
                .map(s -> rootSessionSupplier.get());
        
        return Observable.concat(fromCache, ASExchange).first();
    }

    @Override
    public Observable<String> getRootTicket() {
        Observable<String> fromCache = Observable.create(subscriber -> {
            String rootTicket = serverTGTSupplier.get();
            if (null != rootTicket) {
                subscriber.onNext(rootTicket);
            }
            subscriber.onCompleted();
        });
        Observable<String> ASExchange = authenticationClient.authenticationServiceExchange().doOnNext(response -> {
            String rootTicket = response.getTicketGrantingTicket();
            serverTGTCache.accept(rootTicket); // TGT
            rootSessionCache.accept(response.getSessionKey()); // SK_TGS
        }).map(AuthenticationServiceResponse::getTicketGrantingTicket);


        return Observable.concat(fromCache, ASExchange).first();
    }

    @Override
    public Observable<ClientServerExchangeResponse> handShake(ClientServerExchangeRequest request) {
        return getRootSessionKey().flatMap(rootSessionKey -> Observable.create(subscriber -> {
            try {
                ClientServerExchangeResponse response = clientServerExchangeServer.clientServerExchange(
                        request,
                        getClientSettings().getLocalName(),
                        rootSessionKey
                );
                subscriber.onNext(response);
                subscriber.onCompleted();
            } catch (ServerVerifyException | KerberosCryptoException e) {
                subscriber.onError(Exceptions.propagate(e));
            }
        }));
    }
}
