package git.github.hydroque.JOTP;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;

import java.io.UnsupportedEncodingException;

public class Main {

	
	
	
	public static class SHA1_Encrypt implements OTP_ALGO {
		
		@Override
		public byte[] encrypt(byte[] byte_secret, byte[] byte_string) {
			try {
				SecretKeySpec signingKey = new SecretKeySpec(byte_secret, 0, byte_secret.length, "HmacSHA1");
				Mac mac = Mac.getInstance("HmacSHA1");
				mac.init(signingKey);
				mac.update(byte_string, 0, byte_string.length - 1);
				return mac.doFinal();
			} catch(NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch(InvalidKeyException e) {
				e.printStackTrace();
			}
			return null;
		}
		
	}
	
	
	public static class SHA256_Encrypt implements OTP_ALGO {
		
		@Override
		public byte[] encrypt(byte[] byte_secret, byte[] byte_string) {
			try {
				SecretKeySpec signingKey = new SecretKeySpec(byte_secret, 0, byte_secret.length, "HmacSHA256");
				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(signingKey);
				mac.update(byte_string, 0, byte_string.length - 1);
				return mac.doFinal();
			} catch(NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch(InvalidKeyException e) {
				e.printStackTrace();
			}
			return null;
		}
		
	}
	
	
	public static class SHA512_Encrypt implements OTP_ALGO {
		
		@Override
		public byte[] encrypt(byte[] byte_secret, byte[] byte_string) {
			try {
				SecretKeySpec signingKey = new SecretKeySpec(byte_secret, 0, byte_secret.length, "HmacSHA512");
				Mac mac = Mac.getInstance("HmacSHA512");
				mac.init(signingKey);
				mac.update(byte_string, 0, byte_string.length - 1);
				return mac.doFinal();
			} catch(NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch(InvalidKeyException e) {
				e.printStackTrace();
			}
			return null;
		}
		
	}
	
	
	public static void main(String[] args) {
		
		////////////////////////////////////////////////////////////////
		// Initialization Stuff                                       //
		////////////////////////////////////////////////////////////////
		
		final int INTERVAL	= 30;
		final int DIGITS	= 6;
		
		final byte[] BASE32_SECRET = "JBSWY3DPEHPK3PXP".getBytes(StandardCharsets.US_ASCII);
		final byte[] SHA1_DIGEST = "SHA1".getBytes(StandardCharsets.US_ASCII);
		
		final SHA1_Encrypt ENCRYPTER = new SHA1_Encrypt();
		final int SHA1_BITS = 160;
		
		final TOTP tdata = new TOTP(BASE32_SECRET, SHA1_BITS, ENCRYPTER, SHA1_DIGEST, DIGITS, INTERVAL);
		final HOTP hdata = new HOTP(BASE32_SECRET, SHA1_BITS, ENCRYPTER, SHA1_DIGEST, DIGITS);
		
		System.out.println("\\\\ totp tdata \\\\");
		System.out.println("tdata.getDigits(): `" + tdata.getDigits() + "`");
		System.out.println("tdata.getInterval(): `" + tdata.getInterval() + "`");
		System.out.println("tdata.getBits(): `" + tdata.getBits() + "`");
		System.out.println("tdata.getType(): `" + tdata.getType() + "`");
		System.out.println("tdata.getAlgo(): `" + tdata.getAlgo() + "`");
		System.out.println("tdata.getDigest(): `" + new String(tdata.getDigest(), StandardCharsets.US_ASCII) + "`");
		System.out.println("tdata.getBase32Secret(): `" + new String(tdata.getBase32Secret(), StandardCharsets.US_ASCII) + "`");
		System.out.println("// totp tdata //\n");
		
		System.out.println("\\\\ hotp hdata \\\\");
		System.out.println("hdata.getDigits(): `" + hdata.getDigits() + "`");
		System.out.println("hdata.getBits(): `" + hdata.getBits() + "`");
		System.out.println("hdata.getType(): `" + hdata.getType() + "`");
		System.out.println("hdata.getAlgo(): `" + hdata.getAlgo() + "`");
		System.out.println("hdata.getDigest(): `" + new String(hdata.getDigest(), StandardCharsets.US_ASCII) + "`");
		System.out.println("hdata.getBase32Secret(): `" + new String(hdata.getBase32Secret(), StandardCharsets.US_ASCII) + "`");
		System.out.println("// hotp hdata //\n");
		
		System.out.println("Current Time: `" + (System.currentTimeMillis()/1000) + "`");
		
		
		////////////////////////////////////////////////////////////////
		// URI Example                                                //
		////////////////////////////////////////////////////////////////
		
		final String name1 = "name1";
		final String name2 = "name2";
		final String whatever1 = "account@whatever1.com";
		final String whatever2 = "account@whatever2.com";
		
		// show example of URIs
		
		try {
			// totp uri
			final String uri1 = OTPURI.build_uri(tdata, name1, whatever1, 0);
			
			// hotp uri
			final int counter = 52;
			final String uri2 = OTPURI.build_uri(hdata, name2, whatever2, counter);
			
			
			System.out.println("TOTP URI 1: `" + uri1 + "`\n");
			System.out.println("HOTP URI 2: `" + uri2 + "`\n");
		} catch(UnsupportedEncodingException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		
		////////////////////////////////////////////////////////////////
		// BASE32 Stuff                                               //
		////////////////////////////////////////////////////////////////
		
		// Already seeded the random generator and popped the first result
		
		final int BASE32_LEN = 16;
		
		// Generate random base32
		byte[] base32_new_secret = null;
		try {
			base32_new_secret = tdata.random_base32(BASE32_LEN, OTP.DEFAULT_BASE32_CHARS);
			System.out.println("Generated BASE32 Secret: `" + new String(base32_new_secret, StandardCharsets.US_ASCII) + "`");
		} catch(BASE32FormatError e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		System.out.println(""); // line break for readability
		
		
		////////////////////////////////////////////////////////////////
		// TOTP Stuff                                                 //
		////////////////////////////////////////////////////////////////
		
		// Get TOTP for a time block
		//   1. Generate and load totp key into buffer
		//   2. Check for error
		
		try {
			// totp.now
			int totp_err_1 = tdata.now();
			System.out.println("TOTP Generated: `" + totp_err_1 + "`");
		
			// totp.at
			int totp_err_2 = tdata.at(1, 0);
			System.out.println("TOTP Generated: `" + totp_err_2 + "`");
			
			
			// Do a verification for a hardcoded code
			// Won't succeed, this code is for a timeblock far into the past
			final boolean tv1 = tdata.verify(576203, System.currentTimeMillis()/1000, 4);
			
			// Will succeed, timeblock 0 for JBSWY3DPEHPK3PXP == 282760
			final boolean tv2 = tdata.verify(282760, 0, 4);
			System.out.println("TOTP Verification 1: `" + tv1 + "`");
			System.out.println("TOTP Verification 2: `" + tv2 + "`");
		} catch(HMACGenerationError | BASE32FormatError e) {
			e.printStackTrace();
			System.err.println("TOTP Error 2");
			System.exit(1);
		}
		
		System.out.println(""); // line break for readability
		
		
		////////////////////////////////////////////////////////////////
		// HOTP Stuff                                                 //
		////////////////////////////////////////////////////////////////
		
		// Get HOTP for token 1
		//   1. Generate and load hotp key into buffer
		//   2. Check for error
		
		try {
			final int hotp_err_1 = hdata.at(1);			
			System.out.println("HOTP Generated at 1: `" + hotp_err_1 + "`");
			
			// Do a verification for a hardcoded code
			// Will succeed, 1 for JBSWY3DPEHPK3PXP == 996554
			final boolean hv = hdata.verify(996554, 1);
			System.out.println("HOTP Verification 1: `" + hv + "`");
		} catch(HMACGenerationError | BASE32FormatError e) {
			e.printStackTrace();
			System.err.println("HOTP Error 1");
			System.exit(1);
		}
		
		
	}
	
}

