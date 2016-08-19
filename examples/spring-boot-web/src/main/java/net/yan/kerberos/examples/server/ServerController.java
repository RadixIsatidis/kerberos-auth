package net.yan.kerberos.examples.server;

import net.yan.kerberos.data.ClientServerExchangeRequest;
import net.yan.kerberos.data.ClientServerExchangeResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import rx.Single;

/**
 * @author yanle
 */
@RestController
@RequestMapping("server")
public class ServerController {

    private static final Logger logger = LoggerFactory.getLogger(ServerController.class);

    private final AuthService authService;

    @Autowired
    public ServerController(AuthService authService) {
        this.authService = authService;
    }


    @RequestMapping(value = "tgt", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public Single<String> getTGT() {
        return authService.getTGT().toSingle();
    }

    @RequestMapping(value = "auth", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public Single<ClientServerExchangeResponse> auth(@RequestBody ClientServerExchangeRequest request) {
        return authService.auth(request).toSingle();
//        try {
//
//        } catch (KerberosException e) {
//            logger.error(e.getMessage(), e);
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
//        }
    }
}
