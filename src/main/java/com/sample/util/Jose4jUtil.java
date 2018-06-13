package com.sample.util;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Base64;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.X509Util;
import org.jose4j.keys.resolvers.X509VerificationKeyResolver;
import org.jose4j.lang.JoseException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 *
 *
 *
 * @author cjrequena
 * @version 1.0
 * @see
 * @since JDK1.8
 */
@Log4j2
public class Jose4jUtil {

  /**
   * Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
   *
   * @return
   * @throws JoseException
   */
  public static RsaJsonWebKey createRsaJsonWebKey() throws JoseException {
    return RsaJwkGenerator.generateJwk(2048);
  }

  /**
   * JSON Web Token is a compact URL-safe means of representing claims/attributes to be transferred between two parties.
   *
   * @param claims
   * @param rsaJsonWebKey
   * @return
   * @throws JoseException
   */
  public static String createSignedJwt(JwtClaims claims, RsaJsonWebKey rsaJsonWebKey, String keyId) throws JoseException {

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS so we create a JsonWebSignature object.
    JsonWebSignature jws = new JsonWebSignature();

    // Give the JWK a Key ID (kid), which is just the polite thing to do
    rsaJsonWebKey.setKeyId(keyId);

    // The payload of the JWS is JSON content of the JWT Claims
    jws.setPayload(claims.toJson());

    // The JWT is signed using the private key
    jws.setKey(rsaJsonWebKey.getPrivateKey());

    // Set the Key ID (kid) header because it's just the polite thing to do.
    // We only have one key in this example but a using a Key ID helps
    // facilitate a smooth key rollover process
    jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());


    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

    // Sign the JWS and produce the compact serialization or the complete JWT/JWS
    // representation, which is a string consisting of three dot ('.') separated
    // base64url-encoded parts in the form Header.Payload.Signature
    // If you wanted to encrypt it, you can simply set this jwt as the payload
    // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
    return jws.getCompactSerialization();
  }

  /**
   *
   * JSON Web Token is a compact URL-safe means of representing claims/attributes to be transferred between two parties.
   *
   * @param claims
   * @param privateKey
   * @return
   * @throws JoseException
   */
  public static String createSignedJwt(JwtClaims claims, PrivateKey privateKey, String keyId) throws JoseException {

    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
    // In this example it is a JWS so we create a JsonWebSignature object.
    JsonWebSignature jws = new JsonWebSignature();


    // The payload of the JWS is JSON content of the JWT Claims
    jws.setPayload(claims.toJson());

    // The JWT is signed using the private key
    jws.setKey(privateKey);

    // Set the Key ID (kid) header because it's just the polite thing to do.
    // We only have one key in this example but a using a Key ID helps
    // facilitate a smooth key rollover process
    jws.setKeyIdHeaderValue(keyId);


    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

    // Sign the JWS and produce the compact serialization or the complete JWT/JWS
    // representation, which is a string consisting of three dot ('.') separated
    // base64url-encoded parts in the form Header.Payload.Signature
    // If you wanted to encrypt it, you can simply set this jwt as the payload
    // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
    return jws.getCompactSerialization();
  }

  /**
   *
   * @param rsaJsonWebKey
   * @return
   * @throws InvalidJwtException
   */
  public static JwtConsumer getConsumer(RsaJsonWebKey rsaJsonWebKey) throws InvalidJwtException {
    // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
    // be used to validate and process the JWT.
    // The specific validation requirements for a JWT are context dependent, however,
    // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
    // and audience that identifies your system as the intended recipient.
    // If the JWT is encrypted too, you need only provide a decryption key or
    // decryption key resolver to the builder.
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
      .setRequireExpirationTime() // the JWT must have an expiration time
      .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
      .setRequireSubject() // the JWT must have a subject claim
      .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
      .setExpectedAudience("Audience") // to whom the JWT is intended for
      .setVerificationKey(rsaJsonWebKey.getKey()) // verify the signature with the public key
      .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
          AlgorithmIdentifiers.RSA_USING_SHA256))
      .build(); // create the JwtConsumer instance
    return jwtConsumer;
  }

  /**
   *
   * @param publicKey
   * @return
   * @throws InvalidJwtException
   */
  public static JwtConsumer getConsumer(PublicKey publicKey) throws InvalidJwtException {
    // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
    // be used to validate and process the JWT.
    // The specific validation requirements for a JWT are context dependent, however,
    // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
    // and audience that identifies your system as the intended recipient.
    // If the JWT is encrypted too, you need only provide a decryption key or
    // decryption key resolver to the builder.
    JwtConsumer jwtConsumer = new JwtConsumerBuilder()
      .setRequireExpirationTime() // the JWT must have an expiration time
      .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
      .setRequireSubject() // the JWT must have a subject claim
      .setExpectedIssuer("Issuer") // whom the JWT needs to have been issued by
      .setExpectedAudience("Audience") // to whom the JWT is intended for
      .setVerificationKey(publicKey) // verify the signature with the public key
      .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
          AlgorithmIdentifiers.RSA_USING_SHA256))
      .build(); // create the JwtConsumer instance
    return jwtConsumer;
  }

}
