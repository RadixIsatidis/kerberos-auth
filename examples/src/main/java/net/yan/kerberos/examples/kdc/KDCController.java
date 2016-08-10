package net.yan.kerberos.examples.kdc;

import net.yan.kerberos.data.AuthenticationServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceRequest;
import net.yan.kerberos.data.TicketGrantingServiceResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * @author yanle
 */
@RestController
@RequestMapping("kdc")
public class KDCController {

    private static final Logger logger = LoggerFactory.getLogger(KDCController.class);

    @Autowired
    private KDCService kdcService;


    @RequestMapping(value = "auth", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<String> authentication(@RequestBody AuthenticationServiceRequest request) {
        try {
            return ResponseEntity.ok(kdcService.resolveAuthenticationServiceRequest(request));
        } catch (GeneralSecurityException e) {
            logger.error(e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getLocalizedMessage());
        }
    }

    @RequestMapping(value = "granting", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<TicketGrantingServiceResponse> granting(@RequestBody TicketGrantingServiceRequest request) {
        try {
            return ResponseEntity.ok(kdcService.resolveServerTicket(request));
        } catch (GeneralSecurityException | ClassNotFoundException | IOException e) {
            logger.error(e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }
}
