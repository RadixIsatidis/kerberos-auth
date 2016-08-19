package net.yan.kerberos.examples.server;

import net.yan.kerberos.client.ServerHelper;
import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import rx.Observable;

/**
 * @author yanle
 */
@Service("SERVER")
public class AuthService {

    private final ServerHelper serverHelper;

    @Autowired
    public AuthService(ServerHelper serverHelper) {
        this.serverHelper = serverHelper;
    }


    public Observable<String> getTGT() {
        return serverHelper.getRootTicket();
    }

    public Observable<ClientServerExchangeResponse> auth(ClientServerExchangeRequest request) {
        return serverHelper.handShake(request);
    }
}
