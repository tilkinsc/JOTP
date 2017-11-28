package git.github.hydroque.JOTP;

import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;

import java.io.UnsupportedEncodingException;

public class OTPURI {

	
	public static String build_uri(OTP data, String issuer, String name, int counter) throws UnsupportedEncodingException {
		final String cissuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8.toString());
		
		String postarg = "";
		String otp_type = "";
		switch(data.getType()) {
			case TOTP:
				otp_type = "totp";
				postarg += "&period=" + ((TOTP)data).getInterval();
				break;
			case HOTP:
				otp_type = "hotp";
				postarg += "&counter=" + counter;
				break;
			default:
				otp_type = "otp";
				break;
		}
		
		final String pre = "otpauth://" + otp_type + "/" + cissuer + ":" + URLEncoder.encode(name, StandardCharsets.UTF_8.toString());
		final String args =
			"?secret=" + URLEncoder.encode(new String(data.getBase32Secret(), StandardCharsets.US_ASCII), StandardCharsets.UTF_8.toString()) +
			"&issuer=" + cissuer +
			"&algorithm=" + URLEncoder.encode(new String(data.getDigest(), StandardCharsets.US_ASCII), StandardCharsets.UTF_8.toString()) +
			"&digits=" + String.valueOf(data.getDigits());
		
		return pre + args + postarg;
	}
	
}
