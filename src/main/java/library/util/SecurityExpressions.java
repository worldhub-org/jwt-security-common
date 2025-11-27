package library.util;

import library.AuthenticationMetadata;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

@Component("securityExpressions")
public class SecurityExpressions {

    public boolean hasS2SCallAuthority(Authentication authentication) {

        if (authentication == null || !(authentication.getPrincipal() instanceof AuthenticationMetadata meta)) {
            return false;
        }

        return meta.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(InternalCall.INTERNAL_CALL_AUTHORITY::equals);
    }
}
