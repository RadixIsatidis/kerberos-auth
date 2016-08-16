package net.yan.kerberos.examples.client;

import net.yan.kerberos.core.KerberosException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    public ResponseEntity<String> getSessionKey(@PathVariable("name") String name) {
        try {
            return ResponseEntity.ok(authService.getSessionKey(name));
        } catch (KerberosException e) {
            logger.error(e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getLocalizedMessage());
        }
    }
}
