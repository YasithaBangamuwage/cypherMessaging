
public class Main
{

  public static void main(String... argv) throws Exception
  {

      //https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede
    //https://javaee.github.io/javamail/
    //First generate a public/private key pair
    RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();

    //Our secret message
    String message = "the answer to life the universe and everything";

    //Encrypt the message
    String cipherText = rsaKeyPairGenerator.encrypt(message);

    //Now decrypt it
    String decipheredMessage = rsaKeyPairGenerator.decrypt(cipherText);

    System.out.println(decipheredMessage);

    //Let's sign our message
    //String signature = rsaKeyPairGenerator.sign("foobar");

    //Let's check the signature
   // boolean isCorrect = rsaKeyPairGenerator.verify("foobar", signature);
   // System.out.println("Signature correct: " + isCorrect);
  }
}
