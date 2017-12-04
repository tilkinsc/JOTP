package git.github.hydroque.JOTP;

import java.nio.charset.StandardCharsets;

public class TOTP extends OTP {

	protected int interval;
	
	public TOTP(byte[] base32_secret, int bits, OTP_ALGO algo, byte[] digest, int digits, int interval) {
		super(base32_secret, bits, algo, digest, digits);
		this.interval = interval;
		this.method = OTPType.TOTP;
	}
	
	public boolean compare(int key, int increment, long for_time) {
		return this.compare(
			super.ensure_padding(key).getBytes(StandardCharsets.US_ASCII),
			increment,
			for_time);
	}
	
	public boolean compare(byte[] key, int increment, long for_time) {
		final byte[] time_str = new byte[super.digits];
		this.at(for_time, increment, time_str);
		
		for (int i=0; i<key.length; i++)
			if (i > time_str.length || key[i] != time_str[i])
				return false;
		return true;
	}
	
	public int at(long for_time, int counter_offset) {
		return this.at(for_time, counter_offset, null);
	}
	
	public int at(long for_time, int counter_offset, byte[] out) {
		return super.generate(this.timecode(for_time) + (long)counter_offset, out);
	}
	
	public int now() {
		return this.now(null);
	}
	
	public int now(byte[] out) {
		return super.generate(this.timecode(System.currentTimeMillis()/1000), out);
	}
	
	public boolean verify(int key, long for_time, int valid_window) {
		return this.verify(
			Integer.toString(key).getBytes(StandardCharsets.US_ASCII),
			for_time,
			valid_window);
	}
	
	public boolean verify(byte[] key, long for_time, int valid_window) {
		if (valid_window < 0)
			return false;
		if (valid_window > 0) {
			for (int i=-valid_window; i<valid_window; i++) {
				if (this.compare(key, i, for_time) == true)
					return true;
			}
		}
		return this.compare(key, 0, for_time);
	}
	
	public long valid_until(long for_time, int valid_window) {
		return for_time + (this.interval * valid_window);
	}
	
	public long timecode(long for_time) {
		if (for_time <= 0)
			return 0;
		return (long)((double)for_time/(double)this.interval); 
	}
	
	public int getInterval() {
		return this.interval;
	}
	
	public void setInterval(int interval) {
		this.interval = interval;
	}
	
}

