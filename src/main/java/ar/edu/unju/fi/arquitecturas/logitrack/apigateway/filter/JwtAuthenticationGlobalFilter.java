package ar.edu.unju.fi.arquitecturas.logitrack.apigateway.filter;

import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.AuthenticatedUser;
import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.JwtValidator;
import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.RouteSecurityProperties;
import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.RouteSecurityProperties.Rule;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Filtro global del gateway que centraliza el control de acceso:
 * <ol>
 *   <li>Deja pasar las rutas públicas (login/registro) y las no protegidas.</li>
 *   <li>Extrae el token Bearer de la cabecera {@code Authorization}; si falta o es inválido responde 401.</li>
 *   <li>Autoriza según los roles del JWT y las reglas configuradas; si no corresponde responde 403.</li>
 *   <li>Delega la identidad a los microservicios mediante las cabeceras {@code X-User-Id},
 *       {@code X-User-Name}, {@code X-User-Roles} y {@code X-User-Dni} (si el token trae DNI),
 *       descartando las que envíe el cliente.</li>
 * </ol>
 * Se ejecuta antes de los filtros de ruta (p. ej. RewritePath), por lo que evalúa la ruta externa.
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@Slf4j
@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_NAME = "X-User-Name";
    public static final String HEADER_USER_ROLES = "X-User-Roles";
    /** DNI del usuario: permite a courier y shipment saber qué repartidor o cliente es (LT4-40). */
    public static final String HEADER_USER_DNI = "X-User-Dni";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtValidator jwtValidator;
    private final List<PathPattern> publicPatterns;
    private final List<PathPattern> protectedPatterns;
    private final List<CompiledRule> rules;

    public JwtAuthenticationGlobalFilter(JwtValidator jwtValidator, RouteSecurityProperties properties) {
        PathPatternParser parser = PathPatternParser.defaultInstance;
        this.jwtValidator = jwtValidator;
        this.publicPatterns = properties.publicPaths().stream().map(parser::parse).toList();
        this.protectedPatterns = properties.protectedPaths().stream().map(parser::parse).toList();
        this.rules = properties.rules().stream()
                .map(rule -> new CompiledRule(parser.parse(rule.path()), rule))
                .toList();
        log.info("Gateway: {} rutas públicas, {} rutas protegidas y {} reglas de autorización cargadas",
                publicPatterns.size(), protectedPatterns.size(), rules.size());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        PathContainer path = request.getPath().pathWithinApplication();
        String method = request.getMethod().name();

        if (matchesAny(publicPatterns, path) || !matchesAny(protectedPatterns, path)) {
            log.debug("Ruta pública o no protegida, se deja pasar: {} {}", method, path.value());
            return chain.filter(exchange.mutate().request(stripIdentityHeaders(request, method, path)).build());
        }

        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            log.debug("Token ausente o sin prefijo Bearer en {} {}", method, path.value());
            return writeError(exchange, HttpStatus.UNAUTHORIZED, "Token ausente: se requiere la cabecera Authorization: Bearer <token>");
        }

        AuthenticatedUser user;
        try {
            user = jwtValidator.validate(authorization.substring(BEARER_PREFIX.length()).trim());
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Token JWT rechazado en {} {}: {}", method, path.value(), e.getMessage());
            return writeError(exchange, HttpStatus.UNAUTHORIZED, "Token inválido o expirado");
        }

        Optional<Rule> rule = rules.stream()
                .filter(r -> r.matches(path, method))
                .map(CompiledRule::rule)
                .findFirst();

        if (rule.isEmpty() || Collections.disjoint(rule.get().roles(), user.roles())) {
            log.warn("Acceso denegado a '{}' (roles {}) en {} {}{}", user.username(), user.roles(), method, path.value(),
                    rule.isEmpty() ? ": ninguna regla coincide" : "");
            return writeError(exchange, HttpStatus.FORBIDDEN, "No tenés permisos para acceder a este recurso");
        }

        log.debug("Acceso concedido a '{}' (userId {}, roles {}) en {} {}",
                user.username(), user.userId(), user.roles(), method, path.value());
        ServerHttpRequest mutated = stripIdentityHeaders(request, method, path).mutate()
                .headers(headers -> {
                    if (user.userId() != null) {
                        headers.set(HEADER_USER_ID, user.userId());
                    }
                    if (user.username() != null) {
                        headers.set(HEADER_USER_NAME, user.username());
                    }
                    headers.set(HEADER_USER_ROLES, String.join(",", user.roles().stream().sorted().toList()));
                    if (user.dni() != null) {
                        headers.set(HEADER_USER_DNI, user.dni());
                    }
                })
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    /** Se ejecuta antes que los filtros de ruta (RewritePath tiene orden positivo). */
    @Override
    public int getOrder() {
        return -100;
    }

    /** Elimina cabeceras de identidad enviadas por el cliente para evitar suplantación. */
    private static ServerHttpRequest stripIdentityHeaders(ServerHttpRequest request, String method, PathContainer path) {
        HttpHeaders headers = request.getHeaders();
        if (!headers.containsHeader(HEADER_USER_ID) && !headers.containsHeader(HEADER_USER_NAME)
                && !headers.containsHeader(HEADER_USER_ROLES) && !headers.containsHeader(HEADER_USER_DNI)) {
            return request;
        }
        log.warn("Se descartaron cabeceras de identidad enviadas por el cliente en {} {} (posible suplantación)",
                method, path.value());
        return request.mutate().headers(h -> {
            h.remove(HEADER_USER_ID);
            h.remove(HEADER_USER_NAME);
            h.remove(HEADER_USER_ROLES);
            h.remove(HEADER_USER_DNI);
        }).build();
    }

    private static boolean matchesAny(List<PathPattern> patterns, PathContainer path) {
        return patterns.stream().anyMatch(p -> p.matches(path));
    }

    /**
     * Escribe una respuesta de error JSON con el mismo formato que {@code ApiError} del security-service.
     */
    private static Mono<Void> writeError(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        if (status == HttpStatus.UNAUTHORIZED) {
            response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        String body = "{\"status\":" + status.value()
                + ",\"error\":\"" + status.getReasonPhrase()
                + "\",\"message\":\"" + message
                + "\",\"timestamp\":\"" + Instant.now() + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    /** Regla con su patrón ya compilado. */
    private record CompiledRule(PathPattern pattern, Rule rule) {

        boolean matches(PathContainer path, String method) {
            return pattern.matches(path)
                    && (rule.methods().isEmpty() || rule.methods().stream().anyMatch(method::equalsIgnoreCase));
        }
    }
}
