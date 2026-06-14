package com.swift.apidev.preval.jwt;


import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.annotation.PostConstruct;

@Component
public class JwtOperations {
    private static final Logger log = LoggerFactory.getLogger(JwtOperations.class);

    final KeyStore keystore;
    final String keyAlias;
    final char[] keyPassword;

    //Set variable keystoreLocation to the value of the property "spring.ssl.bundle.jks.channel.keystore.location" from the application configuration. If this property is not set, it defaults to "unknown". This allows the class to log the location of the keystore being used for JWT operations, which can be helpful for debugging and verification purposes.
    @Value("${spring.ssl.bundle.jks.channel.keystore.location:unknown}")
    private String keystoreLocation;

    //The class is initialized with SslBundles. It extracts the security credentials (keystore, alias, and password) configured under the name "channel" in your Spring application properties.
    public JwtOperations(SslBundles sslBundles) {
        SslBundle channelCertificate = sslBundles.getBundle("channel");
        this.keystore = channelCertificate.getStores().getKeyStore();
        this.keyAlias = channelCertificate.getKey().getAlias();
        this.keyPassword = channelCertificate.getKey().getPassword().toCharArray();
    }

    @PostConstruct
    //only runs when Spring creates the bean as part of the application context.
    //the i can see the log infor from the Terminal consol when the application starts up, confirming that the keystore and key alias have been loaded correctly.
    private void logKeyDetails() {
        log.info("JWT keystore location='{}'", keystoreLocation);
        log.info("JWT keyAlias='{}'", keyAlias);
        log.info("Keystore Password='{}'", keyPassword);
        System.out.println("Print JWT keyAlias = " + keyAlias); //this is for testing purpose, to see the log infor from the Terminal consol when the application starts up, confirming that the keystore and key alias have been loaded correctly.
        log.info("JWT keystore type='{}' provider='{}'", keystore.getType(), keystore.getProvider().getName());    
        
    }

    public static void main(String[] args) throws Exception {
        String Test = "This is Swift api code test";
        System.out.println(Test);
        
        
    }

    @SuppressWarnings("UseSpecificCatch")
    //Creating an OAuth2 Assertion
    //This method constructs a standard JWT assertion for OAuth2. It retrieves the token URI from the OAuth2 client registration to set the audience claim. The JWT is signed using the private key from the keystore, and includes claims such as subject, issuer, audience, and timestamps for issuance and expiration. The resulting JWT is returned as a Spring Security Jwt object.
    public Jwt createAssertion(OAuth2AuthorizationContext oAuth2AuthorizationContext)
            throws JwtException{
        final String tokenUri = oAuth2AuthorizationContext.getClientRegistration()
                .getProviderDetails().getTokenUri();
        final String audience = tokenUri.substring("https://".length());

        try {


            //1. Header Setup: It creates a JWSHeader using RS256 (RSA Signature with SHA-256) and attaches the X.509 certificate chain. This allows the receiver to verify the token using the corresponding public key.
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(keyAlias);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .x509CertChain(
                            Collections.singletonList(Base64.encode(certificate.getEncoded())))
                    .type(JOSEObjectType.JWT).build();

            //This will log the JWT header in JSON format, which includes the algorithm used for signing (RS256), the type of the token (JWT), and the X.509 certificate chain. This information is crucial for debugging and ensuring that the JWT is constructed correctly before signing.
            log.info("JWT Header created is - JSON object: {}", header.toJSONObject());


            //2. Claims Construction (Payload): It builds the payload, including: sub , iss, aud, exp
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(Duration.ofSeconds(15));
            
            // @formatter:off
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                    .subject(certificate.getSubjectX500Principal().getName())
                    .jwtID(UUID.randomUUID().toString())
                    .notBeforeTime(Date.from(issuedAt))
                    .issueTime(Date.from(issuedAt))
                    .expirationTime(Date.from(expiresAt))
                    .issuer(oAuth2AuthorizationContext.getClientRegistration().getClientId())
                    .audience(Collections.singletonList(audience))
                    .build();
            // @formatter:on

            log.info("JWT Payload Claim created is - JSON object: {}", jwtClaimsSet.toJSONObject());


            //3. Signing: It calls the private signJwt method, which retrieves the private key from the KeyStore and signs the token. The signed JWT is then serialized and returned as a Spring Security Jwt object, containing the token string, issue time, expiration time, header, and claims.
            SignedJWT signedJwt = signJwt(header, jwtClaimsSet);
            
            //This will log the complete signed JWT in its serialized form, which is the compact string representation that can be transmitted in HTTP headers or other means. This log entry is essential for verifying that the signing process was successful and that the resulting token is correctly formed before it is used in authentication flows.
            log.info("Signed JWT created in its serialized form is ; Assestion for the request body: {}", signedJwt.serialize());

            return new Jwt(signedJwt.serialize(), jwtClaimsSet.getIssueTime().toInstant(),
                    jwtClaimsSet.getExpirationTime().toInstant(), header.toJSONObject(),
                    jwtClaimsSet.getClaims());


        } catch (Exception e) {
            throw new JwtException(e);
        }
    }

    @SuppressWarnings("UseSpecificCatch")
    // 3. Generating a Request Signature (generateSignature)
    // This method is more specialized. It is used to sign specific data payloads.
    // Payload Hashing: It takes a raw byte[] body, encodes it in Base64, and then calculates an SHA-256 digest of that data.
    // Claim Attachment: It adds this digest as a custom claim named "digest" inside the JWT payload.
    // Result: By signing this JWT, you are effectively signing the hash of your request data. The recipient can decode the JWT, extract the digest claim, and compare it against the hash of the request body they received to ensure the data has not been tampered with.
    public String generateSignature(String url, byte[] body) throws JwtException {
        try {
            byte[] base64 = java.util.Base64.getEncoder().encode(body);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(base64);

            X509Certificate certificate = (X509Certificate) keystore.getCertificate(keyAlias);

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .x509CertChain(
                            Collections.singletonList(Base64.encode(certificate.getEncoded())))
                    .type(JOSEObjectType.JWT).build();

            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(Duration.ofSeconds(15));
            
            // @formatter:off
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                    .subject(certificate.getSubjectX500Principal().getName())
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(issuedAt))
                    .expirationTime(Date.from(expiresAt))
                    .audience(Collections.singletonList(url.substring("https://".length())))
                    .claim("digest", java.util.Base64.getEncoder().encodeToString(digest))
                    .build();
            // @formatter:on

            SignedJWT signedJwt = signJwt(header, jwtClaimsSet);

            return signedJwt.serialize();
        } catch (Exception e) {
            throw new JwtException(e);
        }
    }

    // 4. The Signing Mechanism (signJwt)
    // This is the "engine" of the class. It is a helper method used by both public methods:
    // It fetches the PrivateKey from the KeyStore using the provided alias and password.
    // It initializes an RSASSASigner with that private key.
    // It performs the mathematical signing process on the JWSHeader and JWTClaimsSet provided.
    private SignedJWT signJwt(JWSHeader header, JWTClaimsSet jwtClaimsSet)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            JOSEException {
        PrivateKey privateKey = (PrivateKey) keystore.getKey(keyAlias, keyPassword);
        RSASSASigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJwt = new SignedJWT(header, jwtClaimsSet);

        signedJwt.sign(signer);
        
        return signedJwt;
    }


}

