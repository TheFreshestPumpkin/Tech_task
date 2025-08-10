package org.example;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class CrptApi {

    private static final String BASE_URL = "https://markirovka.demo.crpt.tech/";

    private final TimeUnit timeUnit;
    private final int requestLimit;
    private final long timeWindowMillis;

    private final Queue<Long> requestTimestamps = new LinkedList<>();
    private final ReentrantLock lock = new ReentrantLock(true);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    private String token; // bearer token

    public CrptApi(TimeUnit timeUnit, int requestLimit) {
        if (requestLimit <= 0) throw new IllegalArgumentException("requestLimit must be > 0");

        this.timeUnit = timeUnit;
        this.requestLimit = requestLimit;
        this.timeWindowMillis = timeUnit.toMillis(1);
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * Получение токена через УКЭП.
     * @param signerKey приватный ключ для подписи
     */
    public void authenticate(PrivateKey signerKey) throws Exception {
        // Шаг 1: получить uuid + data
        HttpRequest keyReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/auth/cert/key"))
                .GET()
                .build();

        HttpResponse<String> keyResp = httpClient.send(keyReq, HttpResponse.BodyHandlers.ofString());
        if (keyResp.statusCode() != 200) {
            throw new IOException("Auth key request failed: " + keyResp.body());
        }

        AuthKeyResponse keyData = objectMapper.readValue(keyResp.body(), AuthKeyResponse.class);

        // Подписываем data приватным ключом
        String signedBase64 = signDataBase64(keyData.data, signerKey);

        // Шаг 2: отправить uuid + подписанные данные
        AuthTokenRequest tokenReqBody = new AuthTokenRequest(keyData.uuid, signedBase64);
        String tokenJson = objectMapper.writeValueAsString(tokenReqBody);

        HttpRequest tokenReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/auth/cert/"))
                .header("Content-Type", "application/json;charset=UTF-8")
                .POST(HttpRequest.BodyPublishers.ofString(tokenJson))
                .build();

        HttpResponse<String> tokenResp = httpClient.send(tokenReq, HttpResponse.BodyHandlers.ofString());
        if (tokenResp.statusCode() != 200) {
            throw new IOException("Auth token request failed: " + tokenResp.body());
        }

        AuthTokenResponse tokenData = objectMapper.readValue(tokenResp.body(), AuthTokenResponse.class);
        this.token = tokenData.token;
    }

    public void createIntroduceGoodsDocument(Document document) throws IOException, InterruptedException {
        waitForSlot();

        String jsonBody = objectMapper.writeValueAsString(document);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/lp_introduce_goods/create"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() != 200) {
            throw new IOException("Create document failed: " + resp.statusCode() + " - " + resp.body());
        }
    }
    private void waitForSlot() {
        lock.lock();
        try {
            while (true) {
                long now = Instant.now().toEpochMilli();

                while (!requestTimestamps.isEmpty() && now - requestTimestamps.peek() >= timeWindowMillis) {
                    requestTimestamps.poll();
                }

                if (requestTimestamps.size() < requestLimit) {
                    requestTimestamps.add(now);
                    break;
                } else {
                    long waitTime = timeWindowMillis - (now - requestTimestamps.peek());
                    if (waitTime > 0) {
                        lock.unlock();
                        try {
                            Thread.sleep(waitTime);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        lock.lock();
                    }
                }
            }
        } finally {
            lock.unlock();
        }
    }

    // === Подпись данных в base64 ===
    private String signDataBase64(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signedBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signedBytes);
    }


    private static class AuthKeyResponse {
        public String uuid;
        public String data;
    }

    private static class AuthTokenRequest {
        public String uuid;
        public String data;

        public AuthTokenRequest(String uuid, String data) {
            this.uuid = uuid;
            this.data = data;
        }
    }

    private static class AuthTokenResponse {
        public String token;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Document {
        public Description description;
        public String doc_id;
        public String doc_status;
        public String doc_type = "LP_INTRODUCE_GOODS";
        public boolean importRequest;
        public String owner_inn;
        public String producer_inn;
        public String production_date;
        public String production_type;
        public Product[] products;
        public String reg_date;
        public String reg_number;

        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class Description {
            public String participantInn;
        }

        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class Product {
            public String certificate_document;
            public String certificate_document_date;
            public String certificate_document_number;
            public String owner_inn;
            public String producer_inn;
            public String production_date;
            public String tnved_code;
            public String uit_code;
            public String uitu_code;
        }
    }
}
