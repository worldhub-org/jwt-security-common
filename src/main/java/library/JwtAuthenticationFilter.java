package library;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final String header;
    private final String prefix;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider, String header, String prefix) {
        this.tokenProvider = tokenProvider;
        this.header = header;
        this.prefix = prefix;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader(header);
        if (token != null && token.startsWith(prefix)) {
            token = token.substring(prefix.length()).trim();
            AuthenticationMetadata authenticationMetadata = tokenProvider.parseToken(token);
            Authentication auth = new UsernamePasswordAuthenticationToken(authenticationMetadata, token, authenticationMetadata.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }
}

