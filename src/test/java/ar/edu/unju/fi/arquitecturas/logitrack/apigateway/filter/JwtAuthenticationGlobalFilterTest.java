package ar.edu.unju.fi.arquitecturas.logitrack.apigateway.filter;

import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.JwtProperties;
import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.JwtValidator;
import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.RouteSecurityProperties;
import ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security.RouteSecurityProperties.Rule;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationGlobalFilterTest {

    private static final String SECRET = "dGVzdC1zZWNyZXQtcGFyYS1sb2dpdHJhY2stZ2F0ZXdheS0zMmJ5dGVz";
    private static final String OTHER_SECRET = "b3RyYS1jbGF2ZS1zZWNyZXRhLWRpc3RpbnRhLXBhcmEtcHJ1ZWJhcy0zMg==";
    private static final String ISSUER = "logitrack-security-service";
    private static final String SHIPMENT = "/applications/apishipment/api/v1";
    private static final String COURIER = "/applications/apicourier/api/v1";

    private JwtAuthenticationGlobalFilter filter;
    private AtomicReference<ServerWebExchange> forwarded;
    private GatewayFilterChain chain;

    @BeforeEach
    void setUp() {
        RouteSecurityProperties props = new RouteSecurityProperties(
                List.of("/applications/apisecurity/**"),
                List.of("/applications/apishipment/**", "/applications/apicourier/**"),
                List.of(
                        new Rule(SHIPMENT + "/envios", Set.of("POST"), Set.of("ADMIN", "CLIENTE")),
                        new Rule(SHIPMENT + "/envios/**", Set.of("GET"), Set.of("ADMIN", "CLIENTE", "REPARTIDOR")),
                        new Rule(SHIPMENT + "/envios/**", null, Set.of("ADMIN")),
                        new Rule(COURIER + "/repartidores/*/estado", Set.of("PUT"), Set.of("ADMIN", "REPARTIDOR")),
                        new Rule(COURIER + "/repartidores/**", Set.of("GET"), Set.of("ADMIN", "REPARTIDOR")),
                        new Rule(COURIER + "/repartidores/**", null, Set.of("ADMIN"))));
        filter = new JwtAuthenticationGlobalFilter(new JwtValidator(new JwtProperties(SECRET, ISSUER)), props);
        forwarded = new AtomicReference<>();
        chain = exchange -> {
            forwarded.set(exchange);
            return Mono.empty();
        };
    }

    private static String token(String secret, String issuer, long ttlMs, String... roles) {
        Date now = new Date();
        return Jwts.builder()
                .issuer(issuer)
                .subject("usuario")
                .claim("userId", "42")
                .claim("roles", List.of(roles))
                .issuedAt(now)
                .expiration(new Date(now.getTime() + ttlMs))
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret)))
                .compact();
    }

    private static String validToken(String... roles) {
        return token(SECRET, ISSUER, 60_000, roles);
    }

    private MockServerWebExchange run(MockServerHttpRequest request) {
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        filter.filter(exchange, chain).block();
        return exchange;
    }

    @Test
    void sinCabeceraAuthorization_responde401() {
        MockServerWebExchange ex = run(MockServerHttpRequest.get(SHIPMENT + "/envios").build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(forwarded.get()).isNull();
    }

    @Test
    void cabeceraSinPrefijoBearer_responde401() {
        MockServerWebExchange ex = run(MockServerHttpRequest.get(SHIPMENT + "/envios")
                .header(HttpHeaders.AUTHORIZATION, "Basic abc").build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void tokenFirmadoConOtraClave_responde401() {
        MockServerWebExchange ex = run(MockServerHttpRequest.get(SHIPMENT + "/envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(OTHER_SECRET, ISSUER, 60_000, "ADMIN")).build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void tokenExpirado_responde401() {
        MockServerWebExchange ex = run(MockServerHttpRequest.get(SHIPMENT + "/envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(SECRET, ISSUER, -60_000, "ADMIN")).build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void tokenDeOtroEmisor_responde401() {
        MockServerWebExchange ex = run(MockServerHttpRequest.get(SHIPMENT + "/envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token(SECRET, "otro-emisor", 60_000, "ADMIN")).build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void clienteEliminandoRepartidor_responde403() {
        MockServerWebExchange ex = run(MockServerHttpRequest.delete(COURIER + "/repartidores/123")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken("CLIENTE")).build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(forwarded.get()).isNull();
    }

    @Test
    void clienteCancelandoEnvio_responde403() {
        MockServerWebExchange ex = run(MockServerHttpRequest.patch(SHIPMENT + "/envios/1/cancelar")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken("CLIENTE")).build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void repartidorActualizandoSuEstado_pasa() {
        run(MockServerHttpRequest.put(COURIER + "/repartidores/123/estado")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken("REPARTIDOR")).build());
        assertThat(forwarded.get()).isNotNull();
    }

    @Test
    void clienteRegistrandoEnvio_pasaYPropagaIdentidad() {
        run(MockServerHttpRequest.post(SHIPMENT + "/envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken("CLIENTE")).build());
        ServerHttpRequest req = forwarded.get().getRequest();
        assertThat(req.getHeaders().getFirst(JwtAuthenticationGlobalFilter.HEADER_USER_ID)).isEqualTo("42");
        assertThat(req.getHeaders().getFirst(JwtAuthenticationGlobalFilter.HEADER_USER_NAME)).isEqualTo("usuario");
        assertThat(req.getHeaders().getFirst(JwtAuthenticationGlobalFilter.HEADER_USER_ROLES)).isEqualTo("CLIENTE");
        assertThat(req.getHeaders().getFirst(HttpHeaders.AUTHORIZATION)).startsWith("Bearer ");
    }

    @Test
    void cabecerasDeIdentidadFalsificadas_sonReemplazadas() {
        run(MockServerHttpRequest.get(SHIPMENT + "/envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken("CLIENTE"))
                .header(JwtAuthenticationGlobalFilter.HEADER_USER_ROLES, "ADMIN")
                .header(JwtAuthenticationGlobalFilter.HEADER_USER_ID, "1").build());
        ServerHttpRequest req = forwarded.get().getRequest();
        assertThat(req.getHeaders().get(JwtAuthenticationGlobalFilter.HEADER_USER_ROLES)).containsExactly("CLIENTE");
        assertThat(req.getHeaders().get(JwtAuthenticationGlobalFilter.HEADER_USER_ID)).containsExactly("42");
    }

    @Test
    void rutaPublicaDeSeguridad_pasaSinTokenYSinCabecerasFalsificadas() {
        run(MockServerHttpRequest.post("/applications/apisecurity/api/auth/login")
                .header(JwtAuthenticationGlobalFilter.HEADER_USER_ROLES, "ADMIN").build());
        assertThat(forwarded.get()).isNotNull();
        assertThat(forwarded.get().getRequest().getHeaders().getFirst(JwtAuthenticationGlobalFilter.HEADER_USER_ROLES)).isNull();
    }

    @Test
    void rutaProtegidaSinReglaCoincidente_responde403() {
        MockServerWebExchange ex = run(MockServerHttpRequest.get(SHIPMENT + "/otra-cosa")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken("ADMIN")).build());
        assertThat(ex.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }
}
