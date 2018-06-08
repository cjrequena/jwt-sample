package com.sample.util;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Base64;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import static com.sample.util.KeyPairUtil.createKeyPair;
import static org.junit.Assert.*;

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
public class KeyPairUtilTest {

  @Test
  public void createKeyPairDSACase1Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
    KeyPair keyPair = createKeyPair("DSA", 1024);
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairDSACase2Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
    KeyPair keyPair = createKeyPair("DSA", 1024, 888);
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairDHCase1Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 576-bit DH key pair
    KeyPair keyPair = createKeyPair("DH", 576);
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairDHCase2Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 576-bit DH key pair
    KeyPair keyPair = createKeyPair("DH", 576, 888);
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairRSACase1Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit RSA key pair
    KeyPair keyPair = createKeyPair("RSA", 1024);
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairRSACase2Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit RSA key pair
    KeyPair keyPair = createKeyPair("RSA", 1024, 888);
    verifyCreatedKeys(keyPair);
  }

  private void verifyCreatedKeys(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException {
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    log.debug("Generating key/value pair using {} algorithm ", privateKey.getAlgorithm());

    // Get the bytes of the public and private keys
    byte[] privateKeyBytes = privateKey.getEncoded();
    byte[] publicKeyBytes = publicKey.getEncoded();

    // Get the formats of the encoded bytes
    String formatPrivate = privateKey.getFormat(); // PKCS#8
    String formatPublic = publicKey.getFormat(); // X.509

    log.debug("Private Key : {}", Base64.toBase64String(privateKeyBytes));
    log.debug("Public Key : {}", Base64.toBase64String(publicKeyBytes));

    // The bytes can be converted back to public and private key objects
    KeyFactory keyFactory = KeyFactory.getInstance(keyPair.getPrivate().getAlgorithm());
    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);

    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);

    assertEquals(privateKey, privateKey2);
    assertEquals(publicKey, publicKey2);
  }

}
