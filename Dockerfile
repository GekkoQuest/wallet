FROM eclipse-temurin:21-jdk-alpine AS builder

WORKDIR /app

COPY . .
RUN chmod +x mvnw
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jdk-alpine

WORKDIR /app

COPY --from=builder /app/target/wallet-0.0.1-SNAPSHOT.jar app.jar

# Optional: You can expose default dev port for local use
# If you use services such as Render and similar platforms, they may override this with PORT
EXPOSE 8080

ENTRYPOINT ["java", "-Dserver.port=${PORT}", "-Dserver.address=0.0.0.0", "-jar", "app.jar"]
