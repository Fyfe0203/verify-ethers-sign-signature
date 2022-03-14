import com.defi.chainsdk.util.Web3JClient;
import com.log4j.Log4j;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.utils.Numeric;
import java.util.Arrays;

public class Sig {

  @Test
  public void aaa() throws Exception{
    final String address = "0xe5c7649112dd64252d6273bf17245a37b711a886";
    final String signature = "0xe2faba55d928ce7b2da7fd468f08b67c6172e355ed2f59d6bb31a3cceb0ca8771293f3d49afa0cdfdf21a72eb5864b683e0a5b889b72bd936ed45c639507fbe61b";
    final String message = "15492";
    boolean result = false;
    result = isSignatureValid(address,signature,message);
    System.out.println("result : " + result);
    result = false;
    result = isSignatureValidWzh(address,signature,message);
    System.out.println("result : " + result);
    result = false;
    result = validate(signature, message, address);
    System.out.println("result : " + result);
  }

  boolean isSignatureValid(final String address, final String signature, final String message) {
    Log4j.info("isSignatureValid invoked for Address {} with Signature {} and Message {} ", address, signature,
        message);

    final String personalMessagePrefix = "\u0019Ethereum Signed Message:\n";
    //final String personalMessagePrefix = "\\x19Ethereum Signed Message:\n";
    boolean match = false;

    final String prefix = personalMessagePrefix + message.length();

    final byte[] msgHash = Hash.sha3((prefix + message).getBytes(StandardCharsets.UTF_8));
    final byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
    byte v = signatureBytes[64];
    if (v < 27) {
      v += 27;
    }

    final Sign.SignatureData sd = new Sign.SignatureData(v,
        Arrays.copyOfRange(signatureBytes, 0, 32),
        Arrays.copyOfRange(signatureBytes, 32, 64));

    String addressRecovered = null;

    // Iterate for each possible key to recover
    for (int i = 0; i < 4; i++) {
      final BigInteger publicKey = Sign.recoverFromSignature((byte) i, new ECDSASignature(
          new BigInteger(1, sd.getR()),
          new BigInteger(1, sd.getS())), msgHash);

      if (publicKey != null) {
        addressRecovered = "0x" + Keys.getAddress(publicKey);

        if (addressRecovered.equals(address)) {
          match = true;
          break;
        }
      }
    }

    System.out.println(match);
    return match;
  }
  public static final String PERSONAL_MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";

  public static boolean validate(String signature, String message, String address) {
    //参考 eth_sign in https://github.com/ethereum/wiki/wiki/JSON-RPC
    // eth_sign
    // The sign method calculates an Ethereum specific signature with:
    //    sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message))).
    //
    // By adding a prefix to the message makes the calculated signature recognisable as an Ethereum specific signature.
    // This prevents misuse where a malicious DApp can sign arbitrary data (e.g. transaction) and use the signature to
    // impersonate the victim.
    String prefix = PERSONAL_MESSAGE_PREFIX + message.length();
    byte[] msgHash = Hash.sha3((prefix + message).getBytes());

    byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
    byte v = signatureBytes[64];
    if (v < 27) {
      v += 27;
    }

    Sign.SignatureData sd = new Sign.SignatureData(
        v,
        Arrays.copyOfRange(signatureBytes, 0, 32),
        Arrays.copyOfRange(signatureBytes, 32, 64));

    String addressRecovered = null;
    boolean match = false;

    // Iterate for each possible key to recover
    for (int i = 0; i < 4; i++) {
      BigInteger publicKey = Sign.recoverFromSignature(
          (byte) i,
          new ECDSASignature(new BigInteger(1, sd.getR()), new BigInteger(1, sd.getS())),
          msgHash);

      if (publicKey != null) {
        addressRecovered = "0x" + Keys.getAddress(publicKey);

        if (addressRecovered.equals(address)) {
          match = true;
          break;
        }
      }
    }
    return match;
  }


  static boolean isSignatureValidWzh(final String address, final String signature, final String message) {
    Log4j.info("isSignatureValid invoked for Address {} with Signature {} and Message {} ", address, signature,
        message);

    final String personalMessagePrefix = "\u0019Ethereum Signed Message:\n";
    boolean match = false;

    final String prefix = personalMessagePrefix + message.length();
    final byte[] msgHash = Hash.sha3((prefix + message).getBytes());
    final byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
    byte v = signatureBytes[64];
    if (v < 27) {
      v += 27;
    }

    final Sign.SignatureData sd = new Sign.SignatureData(v,
        Arrays.copyOfRange(signatureBytes, 0, 32),
        Arrays.copyOfRange(signatureBytes, 32, 64));

    String addressRecovered = null;

    // Iterate for each possible key to recover
    for (int i = 0; i < 4; i++) {
      final BigInteger publicKey = Sign.recoverFromSignature((byte) i, new ECDSASignature(
          new BigInteger(1, sd.getR()),
          new BigInteger(1, sd.getS())), msgHash);

      if (publicKey != null) {
        addressRecovered = "0x" + Keys.getAddress(publicKey);

        if (addressRecovered.equals(address)) {
          match = true;
          break;
        }
      }
    }

    return match;
  }

}
