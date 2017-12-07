package git.github.hydroque.JOTP;

import java.util.Random;
import java.nio.charset.StandardCharsets;

public class OTP {

	public static enum OTPType {
		OTP, TOTP, HOTP
	}
	
	public static final byte[] DEFAULT_BASE32_CHARS = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
		'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
		'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5',
		'6', '7'
	};
	
	protected int digits;
	protected int bits;
	
	protected OTPType method;
	protected OTP_ALGO algo;
	
	protected byte[] digest;
	protected byte[] base32_secret;
	
	private Random random;
	
	public OTP(byte[] base32_secret, int bits, OTP_ALGO algo, byte[] digest, int digits) {
		random = new Random();
		random.setSeed(System.nanoTime());
		random.nextInt(1);
		this.base32_secret = base32_secret;
		this.bits = bits;
		this.algo = algo;
		this.digest = digest;
		this.digits = digits;
		this.method = OTPType.OTP;
	}
	
	public int generate(long input, byte[] out) {
		final int secret_len = this.base32_secret.length;
		final int desired_secret_len = (secret_len / 8) * 5;
		
		if (this.bits % 8 != 0)
			throw new HMACGenerationError("generate `this.bits` must be divisble by 8 (got " + this.bits + ")");
		
		final int bit_size = this.bits / 8;
		
		final byte[] byte_string = this.int_to_bytestring(input);
		final byte[] byte_secret = this.byte_secret(secret_len, desired_secret_len + 1);
		final byte[] hmac = this.algo.encrypt(byte_secret, byte_string);
		
		if (hmac == null)
			throw new HMACGenerationError("generate `hmac` returned null from supplied decrypt function");
		
		final int offset = (hmac[bit_size - 1] & 0xF);
		final int code =
			(
			 (hmac[offset] & 0x7F) << 24 |
			 (hmac[offset+1] & 0xFF) << 16 |
			 (hmac[offset+2] & 0xFF) << 8 |
			 (hmac[offset+3] & 0xFF)
			) % (int) Math.pow(10, this.digits);
		
		if (out != null) {
			final String data = this.ensure_padding(code);
			System.arraycopy(
				data.getBytes(StandardCharsets.US_ASCII), 0,
				out, 0,
				data.length());
		}
		
		return code;
	}
	
	public byte[] byte_secret(int size, int len) {
		if (size % 8 != 0)
			throw new BASE32FormatError("byte_secret `size` must be divisble by 8 (got " + size + ")");
		
		final byte[] out_str = new byte[len];
		
		int n = 5;
		for (int i=0; ; i++) {
			n = -1;
			out_str[i*5] = 0;
			for (int block=0; block<8; block++) {
				final int offset = (3 - (5*block) % 8);
				final int octet = (block*5) / 8;
				
				int c = 0;
				if (i*8+block < this.base32_secret.length)
					c = this.base32_secret[i*8+block] & 0xFF;
				
				if (c >= 'A' && c <= 'Z')
					n = c - 'A';
				if (c >= '2' && c <= '7')
					n = 26 + c - '2';
				if (n < 0) {
					n = octet;
					break;
				}
				
				out_str[i*5+octet] |= -offset > 0 ? n >> -offset : n << offset;
				if (offset < 0)
					out_str[i*5+octet+1] = (byte)(-(8 + offset) > 0 ? n >> -(8 + offset) : n << (8 + offset));
			}
			if (n < 5)
				break;
		}
		return out_str;
	}
	
	public byte[] int_to_bytestring(long integer) {
		return new byte[]{
				'\0', '\0', '\0', '\0',
				(byte)(integer >> 24), (byte)(integer >> 16), (byte)(integer >> 8), (byte)(integer), '\0'
			};
	}
	
	public byte[] random_base32(int len, byte[] chars) {
		len = len > 0 ? len : 16;
		if (len % 8 != 0)
			throw new BASE32FormatError("random_base32 `len` must be divisble by 8 (got " + len + ")");
		
		final byte[] bytes = new byte[len];
		for (int i=0; i<len; i++)
			bytes[i] = chars[random.nextInt(Integer.MAX_VALUE) % 32];
		return bytes;
	}
	
	public String ensure_padding(int input) {
		final String s_input = String.valueOf(input);
		return (new String(new char[this.digits]).replace("\0", "0"))
					.substring(s_input.length()) + s_input;
	}
	
	public Random getRandom() {
		return random;
	}
	
	public void setRandom(Random random) {
		this.random = random;
	}
	
	public OTPType getType() {
		return this.method;
	}
	
	public OTP_ALGO getAlgo() {
		return this.algo;
	}
	
	public void setAlgo(OTP_ALGO algo) {
		this.algo = algo;
	}
	
	public byte[] getBase32Secret() {
		return this.base32_secret;
	}
	
	public void setBase32Secret(byte[] base32_secret) {
		this.base32_secret = base32_secret;
	}
	
	public byte[] getDigest() {
		return this.digest;
	}
	
	public void setDigest(byte[] digest) {
		this.digest = digest;
	}
	
	public int getDigits() {
		return this.digits;
	}
	
	public void setDigits(int digits) {
		this.digits = digits;
	}
	
	public int getBits() {
		return this.bits;
	}
	
	public void setBits(int bits) {
		this.bits = bits;
	}
	
}

