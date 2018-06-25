package com.sample.util;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 *
 * @author cjrequena
 * @version 1.0
 * @see
 * @since JDK1.8
 */
@Log4j2
public class EncryptionUtil {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   *
   */
  private EncryptionUtil() {
  }

  /**
   * <p>
   * Creates an asymmetric  key pair.
   * </p>
   * <br>
   * Asymmetric keys are used for asymmetric encryption algorithms. Asymmetric encryption algorithms use one key for encryption, and another for decryption. The public key - private
   * key encryption algorithms are examples of asymmetric encryption algorithms.
   *
   * @param keyAlgorithm
   * @param keyBitSize
   * @return
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   */
  public static KeyPair createKeyPair(String keyAlgorithm, int keyBitSize) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
    SecureRandom secureRandom = new SecureRandom();
    keyPairGenerator.initialize(keyBitSize, secureRandom);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    return keyPair;
  }

  /**
   * <p>
   * Creates an asymmetric  key pair.
   * </p>
   * <br>
   * Asymmetric keys are used for asymmetric encryption algorithms. Asymmetric encryption algorithms use one key for encryption, and another for decryption. The public key - private
   * key encryption algorithms are examples of asymmetric encryption algorithms.
   *
   * @param keyAlgorithm
   * @param keyBitSize
   * @param seed
   * @return
   * @throws Exception
   */
  public static KeyPair createKeyPair(String keyAlgorithm, int keyBitSize, long seed) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.setSeed(seed);
    keyPairGenerator.initialize(keyBitSize, secureRandom);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    return keyPair;
  }

  /**
   * <p>
   * Creates a secret (symmetric) key.
   * </p>
   * <br>
   * Symmetric keys are used for symmetric encryption algorithms. Symmetric encryption algorithms use the same key for encryption and decryption.
   *
   *
   * @param keyAlgorithm
   * @param keyBitSize
   * @return
   * @throws NoSuchAlgorithmException
   */
  public static SecretKey createSecretKey(String keyAlgorithm, int keyBitSize) throws NoSuchAlgorithmException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(keyAlgorithm);
    SecureRandom secureRandom = new SecureRandom();
    keyGenerator.init(keyBitSize, secureRandom);
    return keyGenerator.generateKey();
  }

  /**
   *
   * @param secretKey
   * @return
   * @throws InvalidKeySpecException
   * @throws NoSuchAlgorithmException
   */
  public static SecretKey toSecretKey(String secretKey) {
    return new SecretKeySpec(Base64.decode(secretKey),"AES");
  }

  /**
   *
   * @param key
   * @param keyAlgorithm
   * @return
   * @throws InvalidKeySpecException
   */
  public static PublicKey toPublicKey(String key, String keyAlgorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(key));
    KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
    return keyFactory.generatePublic(publicKeySpec);
  }

  /**
   *
   * @param key
   * @param keyAlgorithm
   * @return
   * @throws InvalidKeySpecException
   */
  public static PrivateKey toPrivateKey(String key, String keyAlgorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decode(key));
    KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
    return keyFactory.generatePrivate(privateKeySpec);
  }

  /**
   *
   * @param data
   * @param key
   * @return
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public static String encrypt(String data, Key key, String keyAlgorithm)
    throws InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    Cipher cipher = Cipher.getInstance(keyAlgorithm);
    cipher.init(Cipher.ENCRYPT_MODE, key);
    AlgorithmParameters params = cipher.getParameters();
    byte[] encryptedData = cipher.doFinal(data.getBytes("UTF-8"));
    return Base64.toBase64String(encryptedData);
  }

  /**
   *
   * @param data
   * @param secretKey
   * @return
   * @throws InvalidKeySpecException
   * @throws NoSuchAlgorithmException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   */
  public static String encrypt(String data, String secretKey) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
    return encrypt(data, toSecretKey(secretKey), "AES");
  }


  /**
   *
   * @param data
   * @param publicKey
   * @param keyAlgorithm
   * @return
   * @throws InvalidKeySpecException
   */
  public static String encrypt(String data, String publicKey, String keyAlgorithm) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
    return encrypt(data, toPublicKey(publicKey,keyAlgorithm), keyAlgorithm);
  }

  /**
   *
   * @param data
   * @param key
   * @return
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   * @throws NoSuchPaddingException
   * @throws NoSuchAlgorithmException
   * @throws BadPaddingException
   * @throws IllegalBlockSizeException
   */
  public static String decrypt(String data, Key key, String keyAlgorithm)
    throws InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    Cipher cipher = Cipher.getInstance(keyAlgorithm);
    cipher.init(Cipher.DECRYPT_MODE, key);
    AlgorithmParameters params = cipher.getParameters();
    byte[] decodedData = Base64.decode(data.getBytes("UTF-8"));
    byte[] decryptedData = cipher.doFinal(decodedData);
    return new String(decryptedData);
  }

  /**
   *
   * @param data
   * @param privateKey
   * @param keyAlgorithm
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws NoSuchPaddingException
   * @throws InvalidKeyException
   * @throws UnsupportedEncodingException
   */
  public static String decrypt(String data, String privateKey, String keyAlgorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
    return decrypt(data, toPrivateKey(privateKey, keyAlgorithm),keyAlgorithm);
  }

  public static String decrypt(String data, String secretKey) throws NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
    return decrypt(data, toSecretKey(secretKey),"AES");
  }

}
