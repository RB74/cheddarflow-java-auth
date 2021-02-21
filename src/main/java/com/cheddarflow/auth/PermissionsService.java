package com.cheddarflow.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.cheddarflow.model.Permission;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class PermissionsService {

    @Value("${cflow.permissions.url}")
    private String permissionsUrl;

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final ObjectMapper objectMapper;

    @Autowired
    public PermissionsService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public Permission getPermission(String cognitoId) {
        try {
            final HttpRequest request = HttpRequest.newBuilder()
              .GET()
              .header("Authorization", "Bearer " + cognitoId)
              .timeout(Duration.ofSeconds(10))
              .uri(URI.create(this.permissionsUrl))
              .build();

            final HttpResponse<InputStream> httpResponse =
              this.httpClient.send(request, HttpResponse.BodyHandlers
                .buffering(HttpResponse.BodyHandlers.ofInputStream(), 2048));

            StringBuilder content = new StringBuilder();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(httpResponse.body()))) {
                String line;
                while ((line = in.readLine()) != null) {
                    content.append(line);
                }
            }

            final JsonNode response = this.objectMapper.readTree(content.toString());
            final JsonNode permissions = response.get("permissions");
            return permissions.get("professionalAccess").asBoolean() ? Permission.PROFESSIONAL
              : permissions.get("standardAccess").asBoolean() ? Permission.STANDARD : Permission.BASIC;
        } catch (InterruptedException e) {
            this.logger.error("Service interrupted", e);
        } catch (Exception e) {
            this.logger.error("Error fetching permissions", e);
        }
        return Permission.BASIC;
    }
}
