package com.mobme;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPublicKeySpec;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;

public class EllipticalCurveCrypto {
	private PrivateKey privateKey;
	private PublicKey publicKey;

  EllipticalCurveCrypto(){
  }

  public PrivateKey getPrivateKey(){
    return privateKey;
  }

  public PublicKey getPublicKey(){
    return publicKey;
  }
  public PrivateKey getPrivateKeyHex(){
      byte[] privateKeyBytes = privateKey.getD().toByteArray();
    return toHex(privateKeyBytes);
  }

  public PublicKey getPublicKeyHex(){
    return toHex(publicKey.getQ().getEncoded(true));
  }

  private void setPrivateKey(String pvtKey){
      byte[] privateKeyBytes = privateKey.getD().toByteArray();
    privateKey = pvtKey;
  }

  private void setPublicKey(String pubKey){
   publicKey = pubKey;
  }

	public String toHex(byte[] data) {
	    StringBuilder sb = new StringBuilder();
	    for (byte b: data) {
	      sb.append(String.format("%02x", b&0xff));
	    }
	    return sb.toString();
	 }

	public void generateKeyPair(){
		// Get domain parameters for example curve secp256r1
	    X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
	    ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(),
	                                                             ecp.getG(), ecp.getN(), ecp.getH(),
	                                                             ecp.getSeed());

	    // Generate a private key and a public key
	    AsymmetricCipherKeyPair keyPair;
	    ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
	    ECKeyPairGenerator generator = new ECKeyPairGenerator();
	    generator.init(keyGenParams);
	    keyPair = generator.generateKeyPair();

	    ECPrivateKeyParameters pvtKey = (ECPrivateKeyParameters) keyPair.getPrivate();
	    ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

      setPrivateKey(pvtKey);
      setPublicKey(pubKey);
	}

  public boolean verifySignature(String pubKey,String message, byte[] signature){
    Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
    ecdsaVerify.initVerify(getPublicKeyFromBytes(DatatypeConverter.parseHexBinary(pubKey)));
    ecdsaVerify.update( DatatypeConverter.parseHexBinary(message));
    return ecdsaVerify.verify(signature);
  }

  private static PublicKey getPublicKeyFromBytes(byte[] pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
	    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
	    KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
	    ECNamedCurveSpec params = new ECNamedCurveSpec("prime256v1", spec.getCurve(), spec.getG(), spec.getN());
	    java.security.spec.ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pubKey);
	    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
	    ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
	    return pk;
	}

  public String Sign(String message){
    Signature dsa = Signature.getInstance("SHA1withECDSA");

    dsa.initSign(getPrivateKey());

    String str = message;
    byte[] strByte = str.getBytes("UTF-8");
    dsa.update(strByte);

    /*
     * Now that all the data to be signed has been read in, generate a
     * signature for it
     */

    byte[] realSig = dsa.sign();
    return new BigInteger(1, realSig).toString(16);
  }

}
