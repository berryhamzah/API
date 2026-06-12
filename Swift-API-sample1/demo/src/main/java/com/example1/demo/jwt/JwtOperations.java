package com.example1.demo.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

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

@Component
public class JwtOperations {
    final KeyStore keystore;
    final String keyAlias;
    final char[] keyPassword;

    

    //The class is initialized with SslBundles. It extracts the security credentials (keystore, alias, and password) configured under the name "channel" in your Spring application properties.
    public JwtOperations(SslBundles sslBundles) {
        SslBundle channelCertificate = sslBundles.getBundle("channel");
        this.keystore = channelCertificate.getStores().getKeyStore();
        this.keyAlias = channelCertificate.getKey().getAlias();
        this.keyPassword = channelCertificate.getKey().getPassword().toCharArray();
    
        System.out.println(keystore); 
        


    }

    public static void main(String[] args) throws Exception {
        String Test = "This is a test";
        System.out.println(Test);
    }


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

            System.out.println(header.toJSONObject());        
    


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

            

            //3. Signing: It calls the private signJwt method, which retrieves the private key from the KeyStore and signs the token. The signed JWT is then serialized and returned as a Spring Security Jwt object, containing the token string, issue time, expiration time, header, and claims.
            SignedJWT signedJwt = signJwt(header, jwtClaimsSet);

            return new Jwt(signedJwt.serialize(), jwtClaimsSet.getIssueTime().toInstant(),
                    jwtClaimsSet.getExpirationTime().toInstant(), header.toJSONObject(),
                    jwtClaimsSet.getClaims());
        } catch (Exception e) {
            throw new JwtException(e);
        }
    }

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
