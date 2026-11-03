# =====================================================================
# DOCKERFILE MULTIETAPA - API-GATEWAY (LogiTrack) - Java 25
# =====================================================================

# Etapa 1: construcción con el Maven Wrapper y JDK 25
FROM eclipse-temurin:25-jdk AS build
WORKDIR /app

# Se copia primero el pom para aprovechar la caché de capas de Docker
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN chmod +x mvnw && ./mvnw -B -q dependency:go-offline

COPY src/ src/
RUN ./mvnw -B -q clean package -DskipTests

# Etapa 2: ejecución solo con el JRE 25
FROM eclipse-temurin:25-jre
WORKDIR /app

# Usuario sin privilegios para ejecutar la aplicación
RUN groupadd --system app && useradd --system --gid app --no-create-home app

COPY --from=build /app/target/*.jar app.jar
USER app

EXPOSE 8066

# JWT_SECRET / JWT_ISSUER NO van en la imagen: se inyectan como variables de entorno (ver .env)
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
