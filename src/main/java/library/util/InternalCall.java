package library.util;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("@securityExpressions.hasS2SCallAuthority(authentication)")
public @interface InternalCall {

    String INTERNAL_CALL_AUTHORITY = "S2S_CALL";
}
