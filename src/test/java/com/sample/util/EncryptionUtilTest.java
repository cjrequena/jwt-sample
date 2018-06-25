package com.sample.util;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
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

import static com.sample.util.EncryptionUtil.createKeyPair;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;

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
public class EncryptionUtilTest {

  @Test
  public void createKeyPairDSACase1Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
    KeyPair keyPair = createKeyPair("DSA", 1024);
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairDSACase2Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit Digital Signature Algorithm (DSA) key pair
    KeyPair keyPair = createKeyPair("DSA", 1024, 888);
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairDHCase1Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 576-bit DH key pair
    KeyPair keyPair = createKeyPair("DH", 576);
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairDHCase2Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 576-bit DH key pair
    KeyPair keyPair = createKeyPair("DH", 576, 888);
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairRSACase1Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit RSA key pair
    KeyPair keyPair = createKeyPair("RSA", 1024);
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void createKeyPairRSACase2Test() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    // Generate a 1024-bit RSA key pair
    KeyPair keyPair = createKeyPair("RSA", 1024, 888);
    log.debug("private key: {}", Base64.toBase64String(keyPair.getPrivate().getEncoded()));
    log.debug("public key: {}", Base64.toBase64String(keyPair.getPublic().getEncoded()));
    verifyCreatedKeys(keyPair);
  }

  @Test
  public void encryptionAndDecryptionCase1Test()
    throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
    String classifiedInformation= "CLASSIFIED INFORMATION";
    SecretKey secretKey = EncryptionUtil.createSecretKey("AES", 128);
    SecretKey invalidSecretKey = EncryptionUtil.createSecretKey("AES", 128);

    log.debug("SecretKey: {}", Base64.toBase64String(secretKey.getEncoded()));

    final String encryptedClassifiedInformation = EncryptionUtil.encrypt("CLASSIFIED INFORMATION", secretKey, "AES");
    assertEquals(EncryptionUtil.decrypt(encryptedClassifiedInformation,secretKey,"AES"),classifiedInformation);
    assertNotEquals(EncryptionUtil.decrypt(encryptedClassifiedInformation,secretKey,"AES"),classifiedInformation+"DAMAGE");
    try {
      EncryptionUtil.decrypt(encryptedClassifiedInformation,invalidSecretKey,"AES");
      fail();
    } catch (Exception e) {
      //IGNORE
    }
  }

  @Test
  public void encryptionAndDecryptionCase2Test() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {

    String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJ3EsxTGIyeqDSLuJW7HA93JJI+S4CpX5XyEZmP1YeuORXor7JnmV0uP/vi30hSXnchq7u2/6PWMCgr/lTv2zHWCfcpMGP3YCgWm1YK9l2qSH39BvcoPZ7jOrZ7rLuPc9+IcftPoGICPgzKvSVj5pXqDvLcB/Q1IZMCeaYPnmVgzAgMBAAECgYEAkf6B0YmA4qWEPnyt+xMDSutlf87kzYpE/LLwpTNfh8FCHcojyk7THUOFKNfB+fhLtDjwHOZoR0Ft0butd63siKVgF+mTYOIXtgIGIDs1f84bgLWMPZUAAkRHGAwUEIwOZIfkjar0ru45o5QqPBbsqR+GQWp9Jk5q8M0OY1fuYDECQQDKxSZYyXGpx6X57HPdw/GNN6FzGK3opbV5hote0kZvNu0of/vGeYAeytXNKuKxSEAMdv2SntTF5SpuRvpTdOGPAkEAxy9GzEjKrIFE+0fsuBJff9SdPlNxBsND/fY8SVqLPkLVMyySArHpyzqn4NYmyKb7NuJv9RXdnsz02mN1Q8wFHQJBAIHJRw41gkdFvvsFWfRsYsQdA34EIexzhIDQmYyL0wGEirANmz4irtsGwWqdNJR8xmI0F4Itn8s7L7l+POQGQAkCQAVJCNzk1ZPsPjNYvjxIKIaQ0rdTqX0fc09q2ECuCWHWjie0eA9gPy7oWIoLxK2wWJwlOAlN0jqjf5/H4dWxtTUCQGE4Zue0697sfQzzascAh0pgPo1Oqy8XEVv6FD+Ck00AQnCa3UgizF00G+s5bFKKp+F3l7Ck4TB+8vhmJg/n38I=";
    String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdxLMUxiMnqg0i7iVuxwPdySSPkuAqV+V8hGZj9WHrjkV6K+yZ5ldLj/74t9IUl53Iau7tv+j1jAoK/5U79sx1gn3KTBj92AoFptWCvZdqkh9/Qb3KD2e4zq2e6y7j3PfiHH7T6BiAj4Myr0lY+aV6g7y3Af0NSGTAnmmD55lYMwIDAQAB";
    String secretKey = "NarhNLmyQZKYwjuNzH4B3Q==";

    String classifiedInformation= "CLASSIFIED INFORMATION";

    String encryptedClassifiedInformation = EncryptionUtil.encrypt("CLASSIFIED INFORMATION", publicKey, "RSA");
    assertEquals(EncryptionUtil.decrypt(encryptedClassifiedInformation,privateKey,"RSA"),classifiedInformation);
    assertNotEquals(EncryptionUtil.decrypt(encryptedClassifiedInformation,privateKey,"RSA"),classifiedInformation+"DAMAGE");

    encryptedClassifiedInformation = EncryptionUtil.encrypt("CLASSIFIED INFORMATION", secretKey);
    assertEquals(EncryptionUtil.decrypt(encryptedClassifiedInformation, secretKey), classifiedInformation);
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
