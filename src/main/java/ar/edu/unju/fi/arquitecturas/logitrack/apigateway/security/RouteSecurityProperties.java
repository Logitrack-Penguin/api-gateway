package ar.edu.unju.fi.arquitecturas.logitrack.apigateway.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Set;

/**
 * Reglas de control de acceso por ruta aplicadas en el gateway.
 *
 * <ul>
 *   <li>{@code publicPaths}: rutas que no exigen token (p. ej. login/registro del security-service).</li>
 *   <li>{@code protectedPaths}: rutas que exigen token válido; si no hay regla que coincida, se deniega (403).</li>
 *   <li>{@code rules}: reglas evaluadas en orden; gana la primera cuyo path y método coincidan.</li>
 * </ul>
 * Los patrones usan la sintaxis de {@code PathPattern} de Spring ({@code *}, {@code **}, {@code {var}}).
 *
 * @author Logitrack Penguin
 * @version 1.0
 */
@ConfigurationProperties("logitrack.gateway.security")
public record RouteSecurityProperties(List<String> publicPaths,
                                      List<String> protectedPaths,
                                      List<Rule> rules) {

    public RouteSecurityProperties {
        publicPaths = publicPaths == null ? List.of() : List.copyOf(publicPaths);
        protectedPaths = protectedPaths == null ? List.of() : List.copyOf(protectedPaths);
        rules = rules == null ? List.of() : List.copyOf(rules);
    }

    /**
     * Regla de autorización.
     *
     * @param path    Patrón de ruta externa (tal como llega al gateway).
     * @param methods Métodos HTTP a los que aplica; vacío significa todos.
     * @param roles   Roles autorizados (basta con tener uno).
     */
    public record Rule(String path, Set<String> methods, Set<String> roles) {

        public Rule {
            methods = methods == null ? Set.of() : Set.copyOf(methods);
            roles = roles == null ? Set.of() : Set.copyOf(roles);
        }
    }
}
