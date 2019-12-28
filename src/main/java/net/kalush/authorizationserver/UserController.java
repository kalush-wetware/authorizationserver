package net.kalush.authorizationserver;

import java.security.Principal;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping(value="/user/me", produces = MediaType.APPLICATION_JSON_VALUE)
    public Principal user(Principal principal) {
        return principal;
    }
}
