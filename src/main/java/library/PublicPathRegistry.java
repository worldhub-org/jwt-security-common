package library;

import jakarta.servlet.http.HttpServletRequest;
import library.util.Unauthenticated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class PublicPathRegistry implements RequestMatcher {

    private static final Logger log = LoggerFactory.getLogger(PublicPathRegistry.class);

    private final Set<RequestMatcher> publicPaths;

    public PublicPathRegistry(RequestMappingHandlerMapping requestMapping) {

        this.publicPaths = buildPublicPathRequestMatchers(requestMapping);
        log.info("Discovered [{}] public endpoints.", publicPaths.size());
    }

    @Override
    public boolean matches(HttpServletRequest request) {

        return publicPaths.stream().anyMatch(matcher -> matcher.matches(request));
    }

    private static Set<RequestMatcher> buildPublicPathRequestMatchers(RequestMappingHandlerMapping mapping) {

        return mapping.getHandlerMethods().entrySet().stream()
                .filter(PublicPathRegistry::isHandlerMethodUnauthenticated)
                .flatMap(entry -> {
                    Set<RequestMethod> methods = entry.getKey().getMethodsCondition().getMethods();
                    Set<String> httpMethods = methods.isEmpty()
                            ? Collections.singleton(null)
                            : methods.stream().map(Enum::name).collect(Collectors.toSet());
                    return entry.getKey().getPatternValues()
                            .stream()
                            .flatMap(path -> httpMethods.stream().map(method -> new AntPathRequestMatcher(path, method)));
                })
                .collect(Collectors.toUnmodifiableSet());
    }

    private static boolean isHandlerMethodUnauthenticated(Map.Entry<RequestMappingInfo, HandlerMethod> entry) {
        return entry.getValue().hasMethodAnnotation(Unauthenticated.class) || entry.getValue().getBeanType().isAnnotationPresent(Unauthenticated.class);
    }
}
