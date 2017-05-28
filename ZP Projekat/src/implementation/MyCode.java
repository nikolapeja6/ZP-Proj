package implementation;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import java.security.interfaces.*;
import org.bouncycastle.asn1.*;
import java.security.cert.*;
import java.security.cert.Certificate;

import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyStore.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.*;

import code.GuiException;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

	// private HashMap<String, X509Certificate> localKeyStore = new HashMap<>();
	private KeyStore localKS;
	private static char[] password = "root".toCharArray();
	private static ProtectionParameter localPP = new KeyStore.PasswordProtection(password);
	private static String pathToLocalKS = "lks.p12";

	private String selectedAlias;

	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);

	}

	@Override
	public boolean exportCertificate(File arg0, int arg1) {

		if (arg1 < 0 || arg1 > 1 || arg0 == null) {
			System.out.println("invalid arguments in exportCertificate");
			return false;
		}

		X509Certificate cert = null;
		try {
			cert = (X509Certificate) localKS.getCertificate(selectedAlias);
		} catch (KeyStoreException e1) {
			System.out
					.println("Exception accessing certificate " + selectedAlias + " from localKS in exportCertificate");
			e1.printStackTrace();
			return false;
		}

		String path = arg0.getAbsolutePath() + ".cer";

		if (arg1 == 1)
			try (JcaPEMWriter out = new JcaPEMWriter(new FileWriter(path));) {
				out.writeObject(cert);
			} catch (IOException e) {
				System.out.println("Error creatin PEM certificater");
				e.printStackTrace();
				return false;
			}
		else {
			FileOutputStream out = null;
			try {
				out = new FileOutputStream(path);
				out.write(cert.getEncoded());
			} catch (Exception e) {
				System.out.println("Exception in DER");
				e.printStackTrace();
				return false;
			} finally {
				try {
					out.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

		}
		return true;
	}

	

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {

		Entry e = null;
		try {
			e = localKS.getEntry(arg0, localPP);
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e1) {
			System.out.println("Error accessing entry " + arg0 + " from localKS");
			e1.printStackTrace();
			return false;
		}
		
		
	
		
		FileInputStream fin = null;
		try {
						
			KeyStore ks = KeyStore.getInstance("pkcs12");
			
			if(Files.exists(FileSystems.getDefault().getPath(arg1))){
				fin = new FileInputStream(arg1);
				ks.load(fin, arg2.toCharArray());
				fin.close();
			}
			else 
				ks.load(null, null);
			ks.setEntry(arg0, e, new PasswordProtection(arg2.toCharArray()));
			
			FileOutputStream fout = new FileOutputStream(arg1);
			ks.store(fout, arg2.toCharArray());
			fout.close();
		} catch (Exception ee) {
			System.out.println("Exception with keystore in export keypair");
			ee.printStackTrace();
			return false;
		}

		return true;
	}

	// TODO

	@Override
	public boolean generateCSR(String arg0) {
		
		System.out.println(arg0);

		Entry e = null;
		PrivateKey pr = null;
		PublicKey pu = null;
		X509Certificate c = null;
		try {
			e = localKS.getEntry(arg0, localPP);
			pr = ((PrivateKeyEntry) e).getPrivateKey();
			pu = ((PrivateKeyEntry) e).getCertificate().getPublicKey();
			c = (X509Certificate) ((PrivateKeyEntry) e).getCertificate();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e1) {
			e1.printStackTrace();
			return false;
		}

		if (pr == null || pu == null) {
			System.out.println("Error - private or public key is null");
			return false;
		}

		
		PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
				new X500Principal( c.getSubjectDN().toString()), pu);
		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(c.getSigAlgName());
		ContentSigner signer = null;
		try {
			signer = csBuilder.build(pr);
		} catch (OperatorCreationException e1) {
			e1.printStackTrace();
		}

		PKCS10CertificationRequest csr = p10Builder.build(signer);
		

		System.out.println("generateCSR successfully finished");

		return true;
	}

	@Override
	public String getIssuer(String arg0) {

		if (arg0 == null || arg0.isEmpty()) {
			System.out.println("getIssuer called with null or '' string");
			return null;
		}

		try {
			if (!localKS.isKeyEntry(arg0) && !localKS.isCertificateEntry(arg0)) {
				System.out.println("getIsuer called with a key that is not in the local keystore");
				return null;
			}
		} catch (KeyStoreException e1) {
			e1.printStackTrace();
		}

		// X509Certificate c = localKeyStore.get(arg0);

		X509Certificate c = null;
		try {
			c = (X509Certificate) localKS.getCertificate(arg0);
		} catch (KeyStoreException e) {
			System.out.println("Error getCerticfcate fro loacl KeyStore");
			return null;
		}

		if (c == null) {
			System.out.println("Error - certificate is null in getIssuer");
			return null;
		}

		return c.getIssuerDN().toString().replace(", ", ",");

	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String arg0) {

		if (arg0 == null || arg0.isEmpty()) {
			System.out.println("getIssuerPublicKeyAlgorithm was called with an null or '' string");
			return null;
		}

		try {
			if (!localKS.isKeyEntry(arg0) && !localKS.isCertificateEntry(arg0)) {
				System.out
						.println("getIssuerPublicKeyAlgorithm was called with a key that is not in the local keyStore");
				return null;
			}
		} catch (KeyStoreException e1) {

			e1.printStackTrace();
		}

		X509Certificate c = null;
		try {
			c = (X509Certificate) localKS.getCertificate(arg0);
		} catch (KeyStoreException e) {
			System.out.println("Error getCerticfcate fro loacl KeyStore");
			return null;
		}

		if (c == null) {
			System.out.println("Error certificate is null in getIssuerPublicKeyAlgorithm");
			return null;
		}

		return c.getPublicKey().getAlgorithm();

	}

	

	@Override
	public List<String> getIssuers(String arg0) {

		Enumeration<String> aliases = null;
		try {
			aliases = localKS.aliases();
		} catch (KeyStoreException ee) {
			System.out.println("Error in getIssuers while getting aliases from localKS");
			ee.printStackTrace();
			return null;
		}

		if (aliases == null) {
			System.out.println("Error in getIssuers - aliases is null");
			return null;
		}

		List<String> list = new ArrayList<>();

		for (String alias : Collections.list(aliases)) {

			try {
				if(!localKS.isKeyEntry(alias))
					continue;
			} catch (KeyStoreException e1) {
				e1.printStackTrace();
			}
			
			X509Certificate cert = null;
			try {
				cert = (X509Certificate) localKS.getCertificate(alias);
			} catch (KeyStoreException e) {
				System.out.println("Exception in getIssuers while accessing localKS");
				e.printStackTrace();
			}

			if (cert == null) {
				System.out.println("Error with certificate " + alias + ". It could not be found int the localKS");
				continue;
			}

			try {
				if (cert.getKeyUsage()[5])
					list.add(alias);
			} catch (Exception e) {
			}

		}

		return list;
	}

	@Override
	public int getRSAKeyLength(String arg0) {

		if (arg0 == null || arg0.isEmpty()) {
			System.out.println("getRSAKeyLength called with null or '' string");
			return 0;
		}

		try {
			if (!localKS.isKeyEntry(arg0) && !localKS.isCertificateEntry(arg0)) {
				System.out.println("getRSAKeyLength called with a key that is not in the local keystore");
				return 0;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		X509Certificate c = null;
		try {
			c = (X509Certificate) localKS.getCertificate(arg0);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		if (c == null) {
			System.out.println("Error, certificate is null in getRSAKeyLength");
			return 0;
		}

		int ret = ((RSAPublicKey) c.getPublicKey()).getModulus().bitLength();
		System.out.println("getRSAKeyLength with key " + arg0 + " returns " + ret);

		return ret;

	}

	

	@Override
	public boolean importCertificate(File arg0, String arg1) {

		if (arg0 == null || !arg0.exists() || !arg0.canRead()) {
			System.out.println("invalid input file for importCertificate");
			return false;
		}

		if (arg1 == null || arg1.isEmpty()) {
			System.out.println("name of keypair is invalid in importCertificate");
			return false;
		}
		X509Certificate c = null;

		InputStream inStream = null;
		try {
			inStream = new FileInputStream(arg0);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			c = (X509Certificate) cf.generateCertificate(inStream);
		} catch (Exception e) {
			System.out.println("exception opening input file for certificate in importCertificate");
			return false;
		} finally {
			if (inStream != null) {
				try {
					inStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		if (c == null) {
			System.out.println("Error, certificate is null in importCertificate");
			return false;
		}

		try {
			localKS.setCertificateEntry(arg1, c);
			try {
				FileOutputStream fout = new FileOutputStream(pathToLocalKS);
				localKS.store(fout, MyCode.password);
				fout.close();
			} catch (Exception e2) {
				System.out.println("Error storing localKS to file");
				return false;

			}
		} catch (KeyStoreException e) {

			e.printStackTrace();
			return false;
		}

		return true;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {

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

		InputStream in = null;
		try {
			in = new FileInputStream(arg1);
		} catch (FileNotFoundException e1) {
			System.out.println("Error file input stream");
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
			e = ks.getEntry(arg0, new KeyStore.PasswordProtection(password));
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ee) {
			System.out.println("Error keystore getEntry");
			return false;
		}

		X509Certificate c = null;

		if (e == null) {
			System.out.println("entry is null");
			return false;
		}

		if (localKS == null) {
			System.out.println("localKS is null");
			return false;
		}

		c = (X509Certificate) ((PrivateKeyEntry) e).getCertificate();

		try {
			localKS.setEntry(arg0, e, localPP);
		} catch (KeyStoreException e1) {

			e1.printStackTrace();
			return false;
		}

		System.out.println(c);

		try {
			FileOutputStream fout = new FileOutputStream(pathToLocalKS);
			localKS.store(fout, MyCode.password);
			fout.close();
		} catch (Exception e2) {
			System.out.println("Error storing localKS to file");

		}

		return true;
	}

	// TODO
	
	@Override
	public int loadKeypair(String arg0) {

		System.out.println(arg0);
		selectedAlias = arg0;

		X509Certificate c = null;
		try {

			c = (X509Certificate) localKS.getCertificate(arg0);
			/*
			 * if(localKS.isKeyEntry(arg0)){ Entry eeeee =
			 * localKS.getEntry(arg0, localPP); PrivateKeyEntry x =
			 * (PrivateKeyEntry)eeeee; Certificate cc= (x.getCertificate()); c =
			 * (X509Certificate)cc; }
			 */

		} catch (Exception e) {
			e.printStackTrace();
		}

		if (c == null) {
			System.out.println("Could not find " + arg0 + " in localKeyStore");
			return -1;
		}

		System.out.println(c.toString());

		access.setIssuer(c.getIssuerDN().toString().replace(", ", ","));
		access.setIssuerSignatureAlgorithm(c.getSigAlgName());

		access.setSerialNumber("" + c.getSerialNumber());

		access.setVersion(c.getVersion() - 1);

		access.setNotBefore(c.getNotBefore());
		access.setNotAfter(c.getNotAfter());
		
		

		access.setSubject(c.getSubjectDN().toString().replace(", ", ","));
		access.setPublicKeySignatureAlgorithm(c.getSigAlgName());
		access.setPublicKeyParameter("" + getRSAKeyLength(arg0));
		access.setPublicKeyAlgorithm(c.getPublicKey().getAlgorithm());


		// critical
		Collection<String> critical = c.getCriticalExtensionOIDs();
		if (critical != null)
			for (String s : critical) {
				switch (s) {
				case "2.5.29.15": // KeyUsage
					access.setCritical(2, true);
					break;
				case "2.5.29.17": // Alternative Names
					access.setCritical(5, true);
					break;
				case "2.5.29.54": // inhibit any polocy
					access.setCritical(13, true);
					break;
				}
			}

		// KeyUsage
		if (c.getKeyUsage() != null)
			access.setKeyUsage(c.getKeyUsage());

		// inhibit any policy
		try {
			byte[] b = c.getExtensionValue("2.5.29.54");
			if (b != null)
				access.setInhibitAnyPolicy(true);

		} catch (Exception e) {
		}

		// Alternative names
		Collection<List<?>> l = null;
		try {
			l = c.getSubjectAlternativeNames();
		} catch (CertificateParsingException e1) {
			System.out.println("Exception - SubjectGetALternativeNames in loadKeyPair");
			e1.printStackTrace();
		}

		if (l != null) {
			StringBuilder sb = new StringBuilder();
			for (List<?> a:l){
				int type = Integer.parseInt(a.get(0).toString());
				String s = (String)(a.get(1).toString());
				switch(type){
				case 0: 
					s = "other="+s;
					break;
				case 1: 
					s = "rfc822Name="+s;
					break;
				case 2: 
					s = "dNSName="+s;
					break;
				case 3: 
					s = "x400Address="+s;
					break;
				case 4: 
					s = "directoryName="+s;
					break;
				case 5:
					s = "ediPartyName="+s;
					break;
				case 6: 
					s = "uniformResourceIdentifier="+s;
					break;
				case 7:
					s = "iPAddress="+s;
					break;
				case 8:
					s = "registeredID="+s;
					break;
				}
				sb.append((sb.length() == 0 ? "" : ",") +s);
			}
			System.out.println(sb.toString());
			access.setAlternativeName(5, sb.toString());
		}
		
		
		
		byte[] a = c.getExtensionValue("2.5.29.54");
		if( a!= null){
			System.out.println("inhib");
			for(byte b:a)
				System.out.println(b);
			access.setSkipCerts(""+getSkipCert(a));
		}

		
		 try { 
				Certificate[] chain = localKS.getCertificateChain(arg0);
				if(chain != null){
					System.out.println("chain legth " + chain.length);
					for (Certificate cc :chain )
						System.out.println(cc);
				}
				} catch (Exception e) { e.printStackTrace();}
		

		if (c.getKeyUsage() != null && c.getKeyUsage()[5]) {
			System.out.println("2");
			return 2;
		}
		
		if(c.getSubjectDN().toString().equals(c.getIssuerDN().toString())){
			System.out.println(0);
			return 0;
		}
		else{
			System.out.println(1);
			return 1;
		}
		
		/*
		try {
			c.verify(c.getPublicKey());
			System.out.println("0");
			return 0;
		} catch (Exception e) {
			System.out.println("1");
			return 1;
		}
		*/

	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		System.out.println("load local keystore");

		
		
		try {
			localKS = KeyStore.getInstance("pkcs12");
			File f = new File(pathToLocalKS);
			if(f.exists() && f.canRead()){
			FileInputStream fin = new FileInputStream(pathToLocalKS);
			localKS.load(fin, password);
			fin.close();}
			else
				localKS.load(null, null);

		} catch (Exception e) {
			System.out.println("localKeyStore exception in constructor");
			System.exit(1);
		}

		Enumeration<String> ret = null;

		try {
			if (localKS.size() == 0)
				return null;
			ret = localKS.aliases();
		} catch (KeyStoreException e) {

			e.printStackTrace();
		}

		return ret;

	}

	@Override
	public boolean removeKeypair(String arg0) {

		try {
			if (localKS.isKeyEntry(arg0) || localKS.isCertificateEntry(arg0)) {
				localKS.deleteEntry(arg0);

				try {
					FileOutputStream fout = new FileOutputStream(pathToLocalKS);
					localKS.store(fout, password);
					fout.close();
				} catch (Exception e) {
					System.out.println("Error storing localKS to file");
					return false;
				}

				return true;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		return false;
	}

	@Override
	public void resetLocalKeystore() {
		// called when "reset local keystore button is pressed"

		Enumeration<String> aliases = null;
		try {
			if (localKS.size() != 0)
				aliases = localKS.aliases();
		} catch (Exception e) {
			System.out.println("aliases exception");
			e.printStackTrace();
		}

		if (aliases != null)
			for (String x : Collections.list(aliases)) {
				try {
					System.out.println(x);
					localKS.deleteEntry(x);
				} catch (Exception e) {
					System.out.println("Exception in resetLocalKeystore aliases");
				}
			}

		try {
			FileOutputStream fout = new FileOutputStream(pathToLocalKS);
			localKS.store(fout, password);
			fout.close();
		} catch (Exception e) {
			System.out.println("Error storing localKS to file");
		}

	}

	
	// TODO
	@SuppressWarnings(value = { "all" })
	@Override
	public boolean saveKeypair(String arg0) {

		if (arg0 == null || arg0.isEmpty()) {
			System.out.println("string parameter in saveKeypair is null or ''");
			return false;
		}

		System.out.println(arg0);

		String publicKeyAlgorithm = access.getPublicKeyAlgorithm();
		String signatureAlgorithm = access.getPublicKeySignatureAlgorithm();

		if (publicKeyAlgorithm == null || signatureAlgorithm == null) {
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

		if (kpg == null) {
			System.out.println("error - keyPairGenerator is null in saveKeypair");
			return false;
		}

		String keySizeString = access.getPublicKeyParameter();

		if (keySizeString == null || keySizeString.isEmpty()) {
			System.out.println("KeySizeString is null of empty in saveKeypair");
			return false;
		}

		int keySize = Integer.parseInt(keySizeString);

		kpg.initialize(keySize);

		KeyPair kp = kpg.generateKeyPair();

		if (kp == null) {
			System.out.println("KeyPair is null in saveKeypair");
			return false;
		}

		PublicKey pk = kp.getPublic();

		if (pk == null) {
			System.out.println("publickKey is null in saveKeypair");
			return false;
		}

		// KeyFactory - from key to X509EncodedKeySpec

		// MessageDigest md = MessageDigest.getInstance("SHA-256", "ProviderC");


		/*
		 * V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
		 * certGen.setSerialNumber(new
		 * DERInteger(Integer.parseInt(access.getSerialNumber())));
		 * certGen.setEndDate(new DERUTCTime(access.getNotAfter()));
		 * certGen.setStartDate(new DERUTCTime(access.getNotBefore()));
		 * certGen.setIssuer(new X509Name(access.getIssuer()));
		 * certGen.setSubject(new X509Name(access.getSubject()));
		 * DERObjectIdentifier sigOID =
		 * X509Util.getAlgorithmOID("SHA1WithRSAEncryption");
		 */

		BigInteger serial = new BigInteger(access.getSerialNumber());
		Date notB = access.getNotBefore();
		Date notA = access.getNotAfter();

		X500Name dnName = new X500Name(access.getSubject());
		// certGen.setSerialNumber(serial);
		// certGen.setNotBefore(notB);
		// certGen.setNotAfter(notA);
		// certGen.setSubjectDN(dnName);
		// certGen.setPublicKey(kp.getPublic());
		// certGen.setSignatureAlgorithm(signatureAlgorithm);

		/*
		 * PrivateKey a = null; PublicKey b = null; X509Certificate xxx = null;
		 */
		X500Name x = dnName;/*
	try{
			x = new X500Name(
					((X509Certificate) ((PrivateKeyEntry) localKS.getEntry("ETFrootCA", localPP)).getCertificate())
							.getIssuerDN().toString().replace(",", ", "));
			// certGen.setIssuerDN(x);
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e1) {
			System.out.println("Havent found ETFrootCA to sign certificate in saveKeypair");
			return false;
		}
		*/
		/*
		 * try { certGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
		 * false, new AuthorityKeyIdentifierStructure(xxx)); } catch
		 * (CertificateParsingException e1) { e1.printStackTrace(); }
		 * 
		 */

		JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(x, serial, notB, notA, dnName,
				kp.getPublic());

		// KeyUsage
		boolean[] b = access.getKeyUsage();
		if (b != null && access.isCritical(2)) {
			X509KeyUsage kUsage = new X509KeyUsage((b[0] ? X509KeyUsage.digitalSignature : 0)
					| (b[1] ? X509KeyUsage.nonRepudiation : 0) | (b[2] ? X509KeyUsage.keyEncipherment : 0)
					| (b[3] ? X509KeyUsage.dataEncipherment : 0) | (b[4] ? X509KeyUsage.keyAgreement : 0)
					| (b[5] ? X509KeyUsage.keyCertSign : 0) | (b[6] ? X509KeyUsage.cRLSign : 0)
					| (b[7] ? X509KeyUsage.encipherOnly : 0) | (b[8] ? X509KeyUsage.decipherOnly : 0));

			try {
				certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), access.isCritical(2), // keyusage
						kUsage);
			} catch (Exception e2) {
				System.out.println("Exception adding keyusage to certGen");
				e2.printStackTrace();
			}
		}

		// Subject Alternate Names
		String[] altNames = access.getAlternativeName(5);
		if (altNames != null && altNames.length !=0) {
			List<GeneralName> g = new ArrayList<>();
			System.out.println(altNames);
			for (int i = 0; i < altNames.length; i++){
				String[] parts = altNames[i].split("=");
				switch(parts[0]){
				case "other": 
					break;
					//gn[i] = new GeneralName(0, parts[1]); break;
				
				case "rfc822Name":
					g.add(new GeneralName(GeneralName.rfc822Name, parts[1])); break;
				
				case "dNSName": 
					g.add(new GeneralName(GeneralName.dNSName, parts[1])); break;

				case "x400Address": 
					break;
					//gn[i] = new GeneralName(GeneralName.x400Address, parts[1]); break;

				case "directoryName": 
					g.add(new GeneralName(GeneralName.directoryName, parts[1])); break;

				case "editPartyName":
					break;
					//gn[i] = new GeneralName(GeneralName.ediPartyName, parts[1]); break;

				case "uniformResourceIdentifier":
					g.add(new GeneralName(GeneralName.uniformResourceIdentifier, parts[1])); break;

				case "iPAddress":
					g.add(new GeneralName(GeneralName.iPAddress, parts[1])); break;

				case "registeredID":
					g.add(new GeneralName(GeneralName.registeredID, parts[1])); break;


				}
			}

			try {
				certGen.addExtension(Extension.subjectAlternativeName, access.isCritical(5), new GeneralNames(g.toArray(new GeneralName[g.size()])));
			} catch (CertIOException e2) {
				System.out.println("Exception failed to add extension for alternative names");
				e2.printStackTrace();
			}
		}
		
		// Inhibit any policy
		if(access.getInhibitAnyPolicy()){
			
			int skipCert = Integer.parseInt(access.getSkipCerts());
			try {
				certGen.addExtension(Extension.inhibitAnyPolicy, access.isCritical(13), new DERInteger(skipCert));
			} catch (CertIOException e) {
				System.out.println("Exception - failed to add extension for inhibit any policy");
				e.printStackTrace();
			}
		}
			
			
		 

		/*
		 * for(String s:altNames) try { System.out.println(s);
		 * //certGen.addExtension(new ASN1ObjectIdentifier ("2.5.29.17"),
		 * access.isCritical(5),new X500(s) ); } catch (CertIOException e2) {
		 * System.out.println("Could not add sublect alternate names");
		 * e2.printStackTrace(); }
		 * 
		 */

		ContentSigner sigGen = null;
		try {
			sigGen = new JcaContentSignerBuilder(signatureAlgorithm)
					.setProvider("BC").build(kp.getPrivate());
		} catch (OperatorCreationException e1) {

			e1.printStackTrace();
			return false;
		}
		X509Certificate cert = null;
		try {
			cert = new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
		} catch (CertificateException e1) {
			e1.printStackTrace();
			return false;
		}

		/*
		 * X509Certificate cert = null; try {
		 * 
		 * cert = certGen.generateX509Certificate(a, "BC"); cert.verify(b); }
		 * catch (InvalidKeyException | IllegalStateException |
		 * NoSuchAlgorithmException | SignatureException | CertificateException
		 * | NoSuchProviderException e) { System.out.println(
		 * "Exception in saveKeyPair"); e.printStackTrace(); return false; }
		 */

		if (cert == null) {
			System.out.println("cert is null in saveKeypair");
			return false;
		}
		
		System.out.println(cert.toString());
		

		
		
		

		/*
		 * System.out.println("cert issuer = " + cert.getIssuerDN());
		 * System.out.println("xxx subject = " + xxx.getSubjectDN());
		 */

		try {
			
			// localKS.setKeyEntry(arg0, new PrivateKeyEntry(kp.getPrivate(),new
			// Certificate[]{ cert, localKS.getCertificate("ETFrootCA")}),
			// localPP);

			localKS.setKeyEntry(arg0, kp.getPrivate(), this.password, new X509Certificate[] { cert });
		} catch (Exception e) {
			System.out.println("Exception while adding certificate in localKS in saveKeyPair");
			e.printStackTrace();
			return false;
		}

		try {
			FileOutputStream fout = new FileOutputStream(pathToLocalKS);
			localKS.store(fout, password);
			fout.close();
		} catch (Exception e) {
			System.out.println("Error storing localKS to file");
			return false;
		}

		return true;
	}

	// TODO

	@Override
	public boolean signCertificate(String arg0, String arg1) {
		
		if(arg0 == null || arg1 == null){
			System.out.println("Invalid arguments in signCertificate");
			return false;
		}
		
		X509Certificate old = null;
		
		try {
			old = (X509Certificate)localKS.getCertificate(selectedAlias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		
		if(old == null){
			System.out.println("Certificate witl alias "+selectedAlias+" could not be located in the localKS");
			return false;
		}
		
		PrivateKey pr = null;
		Certificate[] issuerChain = null;
		PublicKey pub = null;
		
		try {
			pr = ((PrivateKeyEntry)localKS.getEntry(arg0, localPP)).getPrivateKey();
			pub = ((PrivateKeyEntry)localKS.getEntry(arg0, localPP)).getCertificate().getPublicKey();
			issuerChain = ((PrivateKeyEntry)localKS.getEntry(arg0, localPP)).getCertificateChain();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		
		if(pr == null || issuerChain == null){
			System.out.println("Error - private key of entry "+arg0+" is null");
			return false;
		}
		
		
		
		String publicKeyAlgorithm = old.getPublicKey().getAlgorithm();	//access.getPublicKeyAlgorithm(); 
		String signatureAlgorithm = arg1;								//access.getPublicKeySignatureAlgorithm();

		if (publicKeyAlgorithm == null || signatureAlgorithm == null) {
			System.out.println("public ketAlgorithm or signature algorithm are null");
			return false;
		}

		

		int keySize = getRSAKeyLength(selectedAlias);	

		PublicKey pk = old.getPublicKey();

		if (pk == null) {
			System.out.println("publickKey is null in saveKeypair");
			return false;
		}
		
		BigInteger serial = old.getSerialNumber();							//new BigInt(access.getSerialNumber()));
		Date notB =	old.getNotBefore();														// access.getNotBefore();
		Date notA = old.getNotAfter();														//access.getNotAfter();

																			//X500Name dnName = new X500Name(access.getSubject()); 
		X500Principal dnName = new X500Principal(old.getSubjectDN().toString().replace(",",", "));
		X500Principal x = new X500Principal(((X509Certificate)issuerChain[0]).getSubjectDN().toString());
		
		Set<String> set = old.getCriticalExtensionOIDs();
		
		
	
	
		JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(x, serial, notB, notA, dnName,pk);

			// KeyUsage
			boolean[] b = old.getKeyUsage();									//access.getKeyUsage();
			if (b != null && set.contains("2.5.29.15")) {
				X509KeyUsage kUsage = new X509KeyUsage((b[0] ? X509KeyUsage.digitalSignature : 0)
						| (b[1] ? X509KeyUsage.nonRepudiation : 0) | (b[2] ? X509KeyUsage.keyEncipherment : 0)
						| (b[3] ? X509KeyUsage.dataEncipherment : 0) | (b[4] ? X509KeyUsage.keyAgreement : 0)
						| (b[5] ? X509KeyUsage.keyCertSign : 0) | (b[6] ? X509KeyUsage.cRLSign : 0)
						| (b[7] ? X509KeyUsage.encipherOnly : 0) | (b[8] ? X509KeyUsage.decipherOnly : 0));
				
				
				try {
					certGen.addExtension(new ASN1ObjectIdentifier("2.5.29.15"),(set != null && set.contains("2.5.29.15")?true:false), // keyusage
							kUsage);
				} catch (Exception e2) {
					System.out.println("Exception adding keyusage to certGen");
					e2.printStackTrace();
				}
			}

			// Subject Alternate Names
			Collection<List<?>> col = null;
			try {
				col = old.getSubjectAlternativeNames();
			} catch (CertificateParsingException e3) {
				e3.printStackTrace();
			}												// access.getAlternativeName(5);

			if (col != null && col.size()>0) {
				List<?>[] arr =new List<?>[col.size()];
				col.toArray(arr);
				GeneralName[] gn = new GeneralName[col.size()];
				for (int i = 0; i < col.size(); i++){
					gn[i] = new GeneralName(Integer.parseInt(arr[i].get(0).toString()), (String)arr[i].get(1));
				}

				try {
					certGen.addExtension(Extension.subjectAlternativeName, (set!=null && set.contains("2.5.29.17")?true:false), new GeneralNames(gn));
				} catch (CertIOException e2) {
					System.out.println("Exception failed to add extension for alternative names");
					e2.printStackTrace();
				}
			}
			
			// Inhibit any policy
			byte[] a = old.getExtensionValue("2.5.29.54");
			if( a!= null){
	
				try {
					certGen.addExtension(Extension.inhibitAnyPolicy, (set!=null && set.contains("2.5.29.54")?true:false), new DERInteger(getSkipCert(a)));
				} catch (CertIOException e) {
					e.printStackTrace();
				}
			}
				

			ContentSigner sigGen = null;
			try {
				sigGen = new JcaContentSignerBuilder(signatureAlgorithm)
						/* .setProvider(BC) */.build(pr);
			} catch (OperatorCreationException e1) {

				e1.printStackTrace();
				return false;
			}
			X509Certificate cert = null;
			try {
				cert = new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
			} catch (CertificateException e1) {
				e1.printStackTrace();
				return false;
			}


			if (cert == null) {
				System.out.println("cert is null in saveKeypair");
				return false;
			}
			System.out.println(cert.toString());

			try {
				Certificate[] chain = new Certificate[issuerChain.length+1];
				for(int i=0; i<issuerChain.length; i++)
					chain[i+1] = issuerChain[i];
				chain[0] = cert;
				
				System.out.println(x);
				System.out.println(cert.getIssuerDN());
				System.out.println(((X509Certificate)chain[1]).getSubjectDN());
				
				cert.checkValidity(new Date());
				cert.verify(pub);
				//localKS.setKeyEntry(arg0, kp.getPrivate(), this.password, chain);
				if(localKS.isKeyEntry(selectedAlias)){
					PrivateKeyEntry e = (PrivateKeyEntry) localKS.getEntry(selectedAlias,localPP );
					localKS.setKeyEntry(selectedAlias, e.getPrivateKey(), this.password, chain);
				}
				else{
					localKS.setCertificateEntry(selectedAlias, cert);
				}
			} catch (Exception e) {
				System.out.println("Exception while adding certificate in localKS in saveKeyPair");
				e.printStackTrace();
				return false;
			}

			try {
				FileOutputStream fout = new FileOutputStream(pathToLocalKS);
				localKS.store(fout, password);
				fout.close();
			} catch (Exception e) {
				System.out.println("Error storing localKS to file");
				return false;
			}

			return true;

	}
	
	private long getSkipCert(byte[] b){
		if(b == null || b.length == 1){
			System.out.println("Error byte array in getSkipCert is null or has length of 1");
			return -1;
		}
		
		int begin = b.length-2;
		while(begin >=0 && b.length-begin-1 != b[begin])
			begin--;
		
		if(begin <0){
			System.out.println("invalid - begin < 0");
			return -2;
		}
		byte[] arr = new byte[8];
	
		
		for(int i = 8-b[begin++]; begin <b.length; begin++, i++)
			arr[i] = b[begin];
			
		
		ByteBuffer wrapped = ByteBuffer.wrap(arr); // big-endian by default
		long ret = wrapped.getLong();

		System.out.println("returning " + ret);
		return ret;
		
	}

}
