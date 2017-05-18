package implementation;

import java.io.*;
import java.math.BigInteger;

import org.bouncycastle.*;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.bouncycastle.x509.*;
import java.security.interfaces.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier.*;
import org.bouncycastle.asn1.*;

import java.security.KeyStore.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import code.GuiException;
import x509.v3.CodeV3;
import org.bouncycastle.asn1.DEROutputStream;

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

	// TODO

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

		arg1 += ".p12";

		try {
			KeyStore ks = KeyStore.getInstance("pkcs12");
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
		System.out.println("generateCSR");
		System.out.println("---------\n");

		return false;
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

	// TODO

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

		Certificate etf;
		try {
			etf = localKS.getCertificate("ETFrootCA");
		} catch (KeyStoreException e1) {
			System.out.println("Exception while accessing  localKS for ETFrootCA in getIssuers");
			e1.printStackTrace();
			return null;
		}

		if (etf == null) {
			System.out.println("Could not find ETFrootCA in getIssuers in localKS");
			return null;
		}

		for (String alias : Collections.list(aliases)) {

			/*
			 * if(alias.equals(arg0)) continue;
			 */
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
				cert.verify(etf.getPublicKey());
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

	// TODO

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
		access.setIssuerSignatureAlgorithm("WHAT????");

		access.setSerialNumber("" + c.getSerialNumber());

		access.setVersion(c.getVersion() - 1);

		access.setNotBefore(c.getNotBefore());
		access.setNotAfter(c.getNotAfter());

		access.setSubject(c.getSubjectDN().toString().replace(", ", ","));
		access.setPublicKeySignatureAlgorithm(c.getSigAlgName());
		access.setPublicKeyParameter("" + getRSAKeyLength(arg0));
		access.setPublicKeyAlgorithm(c.getPublicKey().getAlgorithm());

		X509CertificateHolder cert = null;
		try {
			cert = new X509CertificateHolder(c.getEncoded());
		} catch (CertificateEncodingException | IOException e) {
			e.printStackTrace();
		}

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

		if (c.getKeyUsage() != null)
			access.setKeyUsage(c.getKeyUsage());

		try {
			byte[] b = c.getExtensionValue("2.5.29.54");
			if (b != null)
				access.setInhibitAnyPolicy(true);

		} catch (Exception e) {
		}

		Collection<List<?>> l = null;
		try {
			l = c.getSubjectAlternativeNames();
		} catch (CertificateParsingException e1) {
			System.out.println("Exception - SubjectGetALternativeNames in loadKeyPair");
			e1.printStackTrace();
		}

		if (l != null) {
			Object[] a = l.toArray();
			for (int i = 0; i < a.length; i++) {
				access.setAlternativeName(i, a[i].toString());
				System.out.println(a[i].toString());
			}
		}

		// TODO

		// alternative names

		/*
		 * try { for (Certificate cc : localKS.getCertificateChain(arg0))
		 * System.out.println(cc); } catch (Exception e) { e.printStackTrace();
		 * }
		 * 
		 */

		if (c.getKeyUsage() != null && c.getKeyUsage()[5]) {
			System.out.println("2");
			return 2;
		}

		try {
			c.verify(c.getPublicKey());
			System.out.println("0");
			return 0;
		} catch (Exception e) {
			System.out.println("1");
			return 1;
		}

	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		System.out.println("load local keystore");

		try {
			localKS = KeyStore.getInstance("pkcs12");
			FileInputStream fin = new FileInputStream(pathToLocalKS);
			localKS.load(fin, password);
			fin.close();

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

		// TODO

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
		//certGen.setSerialNumber(serial);
		//certGen.setNotBefore(notB);
		//certGen.setNotAfter(notA);
		//certGen.setSubjectDN(dnName);
		//certGen.setPublicKey(kp.getPublic());
		//certGen.setSignatureAlgorithm(signatureAlgorithm);
		
		/*
		PrivateKey a = null;
		PublicKey b = null;
		X509Certificate xxx = null;
		*/
		X500Name x = null;
		try {
			/*
			a = ((PrivateKeyEntry) localKS.getEntry("ETFrootCA", localPP)).getPrivateKey();
			b = ((PrivateKeyEntry) localKS.getEntry("ETFrootCA", localPP)).getCertificate().getPublicKey();
			xxx = (X509Certificate) ((PrivateKeyEntry) localKS.getEntry("ETFrootCA", localPP)).getCertificate();
			*/
			x = new X500Name(
					((X509Certificate) ((PrivateKeyEntry) localKS.getEntry("ETFrootCA", localPP)).getCertificate())
							.getIssuerDN().toString().replace(",", ", "));
			//certGen.setIssuerDN(x);
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e1) {
			System.out.println("Havent found ETFrootCA to sign certificate in saveKeypair");
			return false;
		}

		/*
		 * try { certGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
		 * false, new AuthorityKeyIdentifierStructure(xxx)); } catch
		 * (CertificateParsingException e1) { e1.printStackTrace(); }
		 * 
		 */

		
		JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(x, serial, notB, notA, dnName, kp.getPublic() );
		 ContentSigner sigGen =null;
		try {
			sigGen = new JcaContentSignerBuilder(signatureAlgorithm)
			         /*.setProvider(BC)*/.build(kp.getPrivate());
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
		X509Certificate cert = null;
		try {

			cert = certGen.generateX509Certificate(a, "BC");
			cert.verify(b);
		} catch (InvalidKeyException | IllegalStateException | NoSuchAlgorithmException | SignatureException
				| CertificateException | NoSuchProviderException e) {
			System.out.println("Exception in saveKeyPair");
			e.printStackTrace();
			return false;
		}
		*/

		if (cert == null) {
			System.out.println("cert is null in saveKeypair");
			return false;
		}
		System.out.println(cert.toString());

		/*
		System.out.println("cert issuer = " + cert.getIssuerDN());
		System.out.println("xxx subject = " + xxx.getSubjectDN());
		*/
		
		try {
			// TODO certificatChain
			// localKS.setKeyEntry(arg0, new PrivateKeyEntry(kp.getPrivate(),new
			// Certificate[]{ cert, localKS.getCertificate("ETFrootCA")}),
			// localPP);

			localKS.setKeyEntry(arg0, kp.getPrivate(), this.password, new X509Certificate[] { cert});
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
		System.out.println("sign certificate");
		System.out.println("---------\n");
		return false;
	}

}
