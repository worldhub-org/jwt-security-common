package library.util;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public final class BaseAuthorities {

    public static final GrantedAuthority S2S_CALL_AUTHORITY = new SimpleGrantedAuthority(InternalCall.INTERNAL_CALL_AUTHORITY);

    private BaseAuthorities() {

    }
}
