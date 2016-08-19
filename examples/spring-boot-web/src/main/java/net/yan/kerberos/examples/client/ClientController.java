package net.yan.kerberos.examples.client;

import net.yan.kerberos.core.KerberosException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rx.Observable;

/**
 * @author yanle
 */
@RestController
@RequestMapping("client")
public class ClientController {

    private static final Logger logger = LoggerFactory.getLogger(ClientController.class);

    private final AuthService authService;

    @Autowired
    public ClientController(AuthService authService) {
        this.authService = authService;
    }

    @RequestMapping("session/{name}")
    public Observable<String> getSessionKey(@PathVariable("name") String name) throws KerberosException {
        return authService.getSessionKey(name);
    }
}
