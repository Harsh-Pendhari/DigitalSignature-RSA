import java.util.Base64;
import java.security.*;

public class DSign {

    private static final String Signing_Algorithm = "SHA256withRSA";
    private static final String RSA = "RSA";

    public static byte[] CreateDigitalSignature(byte[] input, PrivateKey key) throws Exception{
        Signature signature = Signature.getInstance(Signing_Algorithm);
        signature.initSign(key);
        signature.update(input);
        return signature.sign();
    }

    public static KeyPair GenerateKeyPair() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception{
        Signature signature = Signature.getInstance(Signing_Algorithm);
        signature.initVerify(key);
        signature.update(input);
        return signature.verify(signatureToVerify);
    }

    public static void main(String[] args) throws Exception{
        String input = "THIS IS A COMPUTER SCIENCE PORTAL";
        KeyPair keyPair = GenerateKeyPair();
        byte[] signature = CreateDigitalSignature(input.getBytes(), keyPair.getPrivate());
        System.out.println("Signature Value : "+Base64.getEncoder().encodeToString(signature));
        System.out.println("Verification : "+verifyDigitalSignature(input.getBytes(), signature, keyPair.getPublic()));
    }
}