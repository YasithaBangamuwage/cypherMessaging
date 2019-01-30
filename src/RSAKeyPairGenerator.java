import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAKeyPairGenerator
{
  private KeyPair pair;

  public RSAKeyPairGenerator() throws NoSuchAlgorithmException
  {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    this.pair = generator.generateKeyPair();
  }

  public String encrypt(String plainText) throws Exception
  {
    Cipher encryptCipher = Cipher.getInstance("RSA");
    encryptCipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());

    byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

    //cypherTextString = Base64.getEncoder().encodeToString(cipherText);
    return Base64.getEncoder().encodeToString(cipherText);
  }

  public String decrypt(String cipherText) throws Exception
  {
    byte[] bytes = Base64.getDecoder().decode(cipherText);

    Cipher decriptCipher = Cipher.getInstance("RSA");
    decriptCipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());

    return new String(decriptCipher.doFinal(bytes), UTF_8);
  }

  public String decryptWithGivenPrivateKey(String cipherText, String privateKey) throws Exception
  {
    byte[] bytes = Base64.getDecoder().decode(cipherText);

    Cipher decriptCipher = Cipher.getInstance("RSA");
    decriptCipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));

    return new String(decriptCipher.doFinal(bytes), UTF_8);
  }

  private KeyPair getKeyPairFromKeyStore() throws Exception
  {
    //Generated with:
    //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

    InputStream ins = Main.class.getResourceAsStream("/keystore.jks");

    KeyStore keyStore = KeyStore.getInstance("JCEKS");
    keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
    KeyStore.PasswordProtection keyPassword =       //Key password
      new KeyStore.PasswordProtection("s3cr3t".toCharArray());

    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

    java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
    PublicKey publicKey = cert.getPublicKey();
    PrivateKey privateKey = privateKeyEntry.getPrivateKey();

    return new KeyPair(publicKey, privateKey);
  }

  public String sign(String plainText) throws Exception
  {
    Signature privateSignature = Signature.getInstance("SHA256withRSA");
    privateSignature.initSign(pair.getPrivate());
    privateSignature.update(plainText.getBytes(UTF_8));

    byte[] signature = privateSignature.sign();

    return Base64.getEncoder().encodeToString(signature);
  }

  public boolean verify(String plainText, String signature) throws Exception
  {
    Signature publicSignature = Signature.getInstance("SHA256withRSA");
    publicSignature.initVerify(pair.getPublic());
    publicSignature.update(plainText.getBytes(UTF_8));

    byte[] signatureBytes = Base64.getDecoder().decode(signature);

    return publicSignature.verify(signatureBytes);
  }

  public KeyPair getPair()
  {
    return pair;
  }

  private PrivateKey getPrivateKey(String base64PrivateKey)
  {
    PrivateKey privateKey = null;
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
    KeyFactory keyFactory = null;
    try
    {
      keyFactory = KeyFactory.getInstance("RSA");
    }
    catch (NoSuchAlgorithmException e)
    {
      e.printStackTrace();
    }
    try
    {
      privateKey = keyFactory.generatePrivate(keySpec);
    }
    catch (InvalidKeySpecException e)
    {
      e.printStackTrace();
    }
    return privateKey;
  }
}
