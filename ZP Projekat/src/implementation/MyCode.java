package implementation;

import java.io.*;
import java.math.BigInteger;

import org.bouncycastle.*;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.bouncycastle.x509.*;

import java.security.KeyStore.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import code.GuiException;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	
	private HashMap<String, X509Certificate> localKeyStore = new HashMap<>();
	private KeyStore localKS;
	private char[] password = "pn140041d".toCharArray();
	private ProtectionParameter localPP = new KeyStore.PasswordProtection(password);
	

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);
		// TODO Auto-generated constructor stub
	
	
	}
	
	// TODO
	
	@Override
	public boolean exportCertificate(File arg0, int arg1) {
		System.out.println("export certificate");
		System.out.println(arg0 + " " + arg1);
		System.out.println("---------\n");
		return false;
	}

	// TODO
	
	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		System.out.println("exportKeypair");
		System.out.println("---------\n");

		return false;
	}
	
	// TODO

	@Override
	public boolean generateCSR(String arg0) {
		System.out.println("generateCSR");
		System.out.println("---------\n");

		return false;
	}

	@Override
	public String getIssuer(String arg0) {
		
		if(arg0== null || arg0.isEmpty()){
			System.out.println("getIssuer called with null or '' string");
			return null;
		}
		
		
		
		try {
			if(!localKS.isKeyEntry(arg0)){
				System.out.println("getIsuer called with a key that is not in the local keystore");
				return null;
			}
		} catch (KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	
		
		//X509Certificate c = localKeyStore.get(arg0);
		
		X509Certificate c = null;
		try {
			c = (X509Certificate) localKS.getCertificate(arg0);
		} catch (KeyStoreException e) {
			System.out.println("Error getCerticfcate fro loacl KeyStore");
			return null;
		}
		
		if(c == null){
			System.out.println("Error - certificate is null in getIssuer");
			return null;
		}
		
		return Data.getInfoIssuer(c.toString());
		
		
		// ??????????? Jel se ovo ovako trazi
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String arg0) {

		System.out.println("---------\n");
		
		if(arg0 == null || arg0.isEmpty()){
			System.out.println("getIssuerPublicKeyAlgorithm was called with an null or '' string");
			return null;
		}
		
		try {
			if(!localKS.isKeyEntry(arg0)){
				System.out.println("getIssuerPublicKeyAlgorithm was called with a key that is not in the local keyStore");
			}
		} catch (KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		//X509Certificate c = localKeyStore.get(arg0);
		
		X509Certificate c = null;
		try {
			c = (X509Certificate) localKS.getCertificate(arg0);
		} catch (KeyStoreException e) {
			System.out.println("Error getCerticfcate fro loacl KeyStore");
			return null;
		}
		
		
		
		if(c == null){
			System.out.println("Error certificate is null in getIssuerPublicKeyAlgorithm");
			return null;
		}
		
		return c.getPublicKey().getAlgorithm();
				
	}
	
	// TODO

	@Override
	public List<String> getIssuers(String arg0) {


		
		
		return null;
	}

	@Override
	public int getRSAKeyLength(String arg0) {
		
		if(arg0== null || arg0.isEmpty()){
			System.out.println("getRSAKeyLength called with null or '' string");
			return 0;
		}
		
		try {
			if(!localKS.isKeyEntry(arg0)){
				System.out.println("getRSAKeyLength called with a key that is not in the local keystore");
				return 0;
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		X509Certificate c = null;
		try {
			c = (X509Certificate) localKS.getCertificate(arg0);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		if(c == null){
			System.out.println("Error, certificate is null in getRSAKeyLength");
			return 0;
		}
		
		int ret = Data.length(c.getPublicKey().toString());
		
		System.out.println("getRSAKeyLength with key " + arg0+" returns "+ ret);
		
		return ret;
		
	}

	@Override
	public boolean importCertificate(File arg0, String arg1) {
		System.out.println(arg0 + " " + arg1);
		System.out.println("---------\n");
		
		if(arg0 == null || !arg0.exists() || !arg0.canRead()){
			System.out.println("invalid input file for importCertificate");
			return false;
		}
		
		if(arg1 == null || arg1.isEmpty()){
			System.out.println("name of keypair is invalid in importCertificate");
			return false;
		}
		X509Certificate c =null;
		
		InputStream inStream = null;
		 try {
		     inStream = new FileInputStream(arg0);
		     CertificateFactory cf = CertificateFactory.getInstance("X.509");
		     c = (X509Certificate)cf.generateCertificate(inStream);
		 } catch (Exception e){
			 System.out.println("exception openin input file for certificate in importCertificate");
			 return false;
		 }finally {
		     if (inStream != null) {
		         try {
					inStream.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		     }
		 }
		 
		 if(c == null){
			 System.out.println("Error, certificate is null in importCertificate");
			 return false;
		 }
		 
	
		 
		 try {
			localKS.setCertificateEntry(arg1, c);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		 
		return false;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {
		// called when Import(.p12) is pressed

		// arg0 - name of the .p12 (ETFrootCA)
		// arg1 - path to the file (C:\Users\Peja\Desktop\Zastita
		// Podataka\Projekat\Postavka\ETFrootCA.p12)
		// arg2 - code for the authority

		// returns true if import is successful

		KeyStore ks = null;

		try {
			ks = KeyStore.getInstance("pkcs12");
		} catch (KeyStoreException e) {
			System.out.println("KeyStore exception");
			return false;
		}

		if (ks == null) {
			System.out.println("KeyStore is null");
			return false;
		}

		File f = new File(arg1);
		if (f == null || !f.exists() | !f.canRead()) {
			System.out.println("input file error");
			return false;

		}

		InputStream in = null;
		try {
			in = new FileInputStream(f);
		} catch (FileNotFoundException e1) {
			System.out.println("Error file input stream");
			return false;
		}

		if (in == null) {
			System.out.println("input stream is null");
			return false;
		}

		char[] password = arg2.toCharArray();

		try {
			ks.load(in, password);
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			System.out.println("Error keystore load");
			return false;
		}

		Entry e = null;

		try {
			e =  ks.getEntry(arg0, new KeyStore.PasswordProtection(password));
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ee) {
			System.out.println("Error keystore getEntry");
			return false;
		}

		X509Certificate c = null;

		if (e == null) {
			System.out.println("entry is null");
			return false;
		}
		
		if(localKS == null)
		{
			System.out.println("localKS is null");
			return false;
		}
		
		
		
		try {
			localKS.setEntry(arg0, e, localPP);
		} catch (KeyStoreException e1) {
			
			e1.printStackTrace();
		}
		
		

		c = (X509Certificate) ((PrivateKeyEntry) e).getCertificate();

		System.out.println(c);
		
		c.getPublicKey().getAlgorithm();
		
	
		
		System.out.println(c.getPublicKey().getAlgorithm());


		return true;
	}

	@Override
	public int loadKeypair(String arg0) {
		// called when selecting a keypair from the list

		// arg0 - name of the keypair

		// return - -1 error
		// 2 == signed, disalbes sign button
		// other unsigned - enables the sign button
		
		X509Certificate c = null;
		try {
			c = (X509Certificate) localKS.getCertificate(arg0);
		} catch (KeyStoreException e) {
			
			
			try{
				
				PrivateKeyEntry x = (PrivateKeyEntry)localKS.getEntry(arg0, localPP);
				c = (X509Certificate)(x.getCertificate());
			}catch(Exception ee){
				ee.printStackTrace();
			}
		}
		if(c == null){
			System.out.println("Could not find "+arg0+" in localKeyStore");
			return -1;
		}
		
		access.setIssuer(Data.getInfoIssuer(c.toString()));
		access.setIssuerSignatureAlgorithm("WHAT???"/*Data.getSignatureAlgorithm(c.toString())*/);
		
		access.setSerialNumber(""+c.getSerialNumber());
		
		access.setVersion(c.getVersion()-1);
		
		
		access.setNotBefore(c.getNotBefore());
		access.setNotAfter(c.getNotAfter());
		
				
		
		access.setSubject(Data.getInfoSubject(c.toString()));
		access.setPublicKeySignatureAlgorithm(Data.getSignatureAlgorithm(c.toString()));
		access.setPublicKeyParameter(""+Data.length(c.getPublicKey().toString()));
		access.setPublicKeyAlgorithm(c.getPublicKey().getAlgorithm());

		access.setKeyUsage(c.getKeyUsage());
	
		// extended key usage
		
		
		System.out.println(getIssuerPublicKeyAlgorithm(arg0));		

		// TODO
		
		// alternative names
		
		if(c.getSignature() != null)
			return 2;
		else
			return 1;
		
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		System.out.println("load local keystore");
		System.out.println("---------\n");
		
		if(localKS == null){
			try {
				localKS = KeyStore.getInstance("pkcs12");
				FileInputStream fin = new FileInputStream("lks.p12");
				localKS.load(fin, password);
				fin.close();
				

			} catch (Exception e) {
				System.out.println("localKeyStore exception in constructor");
				System.exit(1);
			}
		}
			
		
		Enumeration<String> ret = null;
		
		try {
			if(localKS.size() == 0)
				return null;
			ret = localKS.aliases();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return ret;


	}

	@Override
	public boolean removeKeypair(String arg0) {
		System.out.println("remove kaypair");
		System.out.println("---------\n");
		
		try {
			if(localKS.isKeyEntry(arg0)){
				localKS.deleteEntry(arg0);
				return true;
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;
	}

	// TODO
	
	@Override
	public void resetLocalKeystore()  {
		// called when "reset local keystore button is pressed"

		// no arguments

		// no return value
		
		try {
			if(localKS.size() == 0)
				return;
		} catch (KeyStoreException e1) {
			System.out.println("localKS size exception in resetLocalKeystore");
			e1.printStackTrace();
		}
		
		Enumeration<String> aliases = null;
		try {
			aliases = localKS.aliases();
		} catch (Exception e) {
				System.out.println("aliases exception");
				e.printStackTrace();
		}
		
		if(aliases == null){
			System.out.println("Error - aliases is null in resetLocalKeystore");
			return;
		}
		
		while(aliases.hasMoreElements()){
			try {
				System.out.println(aliases.toString());

				localKS.deleteEntry(aliases.toString());
				aliases.nextElement();
			} catch (Exception e) {
				System.out.println("Exception in resetLocalKeystore aliases");
			}
		}
		
		

	}
	
	// TODO

	@Override
	public boolean saveKeypair(String arg0) {
		// called when "Save" is pressed

		// arg0 - name entered
		// requires "Common Name (CN)*" and "Serial Number" to operate, along
		// with arg0
		// data from the "Certificate Subject" can be obtained trough
		// (mainFrame) window.getSubjectInfo(i=1 to 7 (not inclusive))

		// serial number can be obtained by mainFrame.getSerialNumber();

		// return - if operation was successful
		
		
		if(arg0 == null || arg0.isEmpty()){
			System.out.println("string parameter in saveKeypair is null or ''");
			return false;
		}
		
		String publicKeyAlgorithm = access.getPublicKeyAlgorithm();
		String signatureAlgorithm = access.getPublicKeySignatureAlgorithm();
		
		if(publicKeyAlgorithm== null || signatureAlgorithm == null){
			System.out.println("public ketAlgorithm or signature algorithm are null");
			return false;
		}
		
		KeyPairGenerator kpg = null;
		try {
			 kpg = KeyPairGenerator.getInstance(publicKeyAlgorithm);
		} catch (NoSuchAlgorithmException e) {
				System.out.println("KeyPairGenerator exception in saveKeypair");
				return false;
		}
		
		if(kpg == null){
			System.out.println("error - keyPairGenerator is null in saveKeypair");
			return false;
		}
		
		String keySizeString = access.getPublicKeyParameter();
		
		if(keySizeString == null || keySizeString.isEmpty()){
			System.out.println("KeySizeString is null of empty in saveKeypair");
			return false;
		}
		
		int keySize = Integer.parseInt(keySizeString);
		
		kpg.initialize(keySize);
		
		KeyPair kp = kpg.generateKeyPair();
		
		if(kp == null){
			System.out.println("KeyPair is null in saveKeypair");
			return false;
		}
		
		PublicKey pk = kp.getPublic();
		
		PublicKeyFactory pkf = new PublicKeyFactory();
		SubjectPublicKeyInfo s = new SubjectPublicKeyInfo()
		
		if(pk == null){
			System.out.println("publickKey is null in saveKeypair");
			return false;
		}
		
		// KeyFactory - from key to X509EncodedKeySpec

		
		// MessageDigest md = MessageDigest.getInstance("SHA-256", "ProviderC");
		
		
		System.out.println(access.getSubject());
		
		// TODO
		
		/*
		V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
		certGen.setSerialNumber(new DERInteger(Integer.parseInt(access.getSerialNumber())));
		certGen.setEndDate(new DERUTCTime(access.getNotAfter()));
		certGen.setStartDate(new DERUTCTime(access.getNotBefore()));
		certGen.setIssuer(new X509Name(access.getIssuer()));
		certGen.setSubject(new X509Name(access.getSubject()));
        DERObjectIdentifier sigOID = X509Util.getAlgorithmOID("SHA1WithRSAEncryption");		
		*/
		
		
		X500Name issuer = new X500Name("NAMEOFTHEISSUER");
		BigInteger serial = new BigInteger(access.getSerialNumber());
		Date notB = access.getNotBefore();
		Date notA = access.getNotAfter();
		X500Name subject = new X500Name(access.getSubject());
		RSAKeyParameters r = new RSAKeyParameters(false, pk.get);
		BcX509v3CertificateBuilder xcb = new BcX509v3CertificateBuilder(issuer, serial, notB, notA, subject, pk);

		return false;
	}
	
	// TODO

	@Override
	public boolean signCertificate(String arg0, String arg1) {
		System.out.println("sign certificate");
		System.out.println("---------\n");
		return false;
	}

}
