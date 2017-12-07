package git.github.hydroque.JOTP;

import java.nio.charset.StandardCharsets;

public class HOTP extends OTP {

	
	
	public HOTP(byte[] base32_secret, int bits, OTP_ALGO algo, byte[] digest, int digits) {
		super(base32_secret, bits, algo, digest, digits);
		this.method = OTPType.HOTP;
	}
	
	public boolean compare(int key, int counter) {
		return this.compare(
			super.ensure_padding(key).getBytes(StandardCharsets.US_ASCII),
			counter);
	}
	
	public boolean compare(byte[] key, int counter) {
		final byte[] cnt_str = new byte[super.digits];
		this.at(counter, cnt_str);
		
		for (int i=0; i<key.length; i++) {
			if (i > cnt_str.length || key[i] != cnt_str[i])
				return false;
		}
		return true;
	}
	
	public int at(int counter) {
		return this.at(counter, null);
	}
		
	public int at(int counter, byte[] out) {
		return super.generate(counter, out);
	}
	
	public boolean verify(int key, int counter) {
		return this.verify(
			super.ensure_padding(key).getBytes(StandardCharsets.US_ASCII),
			counter);
	}
	
	public boolean verify(byte[] key, int counter) {
		return this.compare(key, counter);
	}
	
}

