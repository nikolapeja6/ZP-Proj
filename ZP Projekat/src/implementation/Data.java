package implementation;

import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Data {
	
	

	private static String CN = "CN=([\\w\\ ]+)";
	private static String OU = "OU=([\\w\\ ]+)";
	private static String O = "O=([\\w\\ ]+)";
	private static String ST = "ST=([\\w\\ ]+)";
	private static String C = "C=([\\w\\ ]+)";
	private static String L = "L=([\\w\\ ]+)";
	
	
	private static Pattern signatureAlgorithm = Pattern.compile("Signature Algorithm: ([\\w\\s]+)");
	private static Pattern keyLength = Pattern.compile("modulus: (\\d+)");
	
	private static Pattern signed = Pattern.compile("Signature:");
	
	// CA - alternative name? / emailAddress

	
	private static String[] patterns = { CN, OU, O, ST, C, L };
	private static String[] names = { "CN", "OU", "O", "ST", "C", "L" };

	public static void main(String[] args) {

	}

	public static String getInfoSubject(String src) {
		StringBuilder sc = new StringBuilder("");
		boolean first = true;
		String begin = "Subject:.*";
		
		for (int i = 0; i < patterns.length; i++) {
			Matcher m = Pattern.compile(begin+patterns[i]).matcher(src);
			if (m.find()) {
				if (!first)
					sc.append(",");
				else
					first = false;
				sc.append(names[i]);
				sc.append("=");
				sc.append(m.group(1));
			}
		}

		System.out.println("Extracted data:\n\n" + sc.toString());

		return sc.toString();

	}
	
	public static String getInfoIssuer(String src) {
		StringBuilder sc = new StringBuilder("");
		boolean first = true;
		String begin = "Issuer:.*";
		
		for (int i = 0; i < patterns.length; i++) {
			Matcher m = Pattern.compile(begin+patterns[i]).matcher(src);
			if (m.find()) {
				if (!first)
					sc.append(",");
				else
					first = false;
				sc.append(names[i]);
				sc.append("=");
				sc.append(m.group(1));
			}
		}

		System.out.println("Extracted data:\n\n" + sc.toString());

		return sc.toString();

	}

	public static String getSignatureAlgorithm(String src) {
		Matcher m = signatureAlgorithm.matcher(src);

		if (!m.find())
			return "";

		return m.group(1);
	}

	public static boolean isSigned(String src) {
		Matcher m = signed.matcher(src);
		if (m.find())
			return true;
		else
			return false;

	}
	
	public static int length(String src){
		Matcher m = keyLength.matcher(src);
		if(m.find())
			return (new BigInteger(m.group(1), 10)).bitLength();
		return 0;
	}
	
	

}
