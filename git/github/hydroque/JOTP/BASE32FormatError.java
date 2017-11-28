package git.github.hydroque.JOTP;

public class BASE32FormatError extends RuntimeException {
	
	public BASE32FormatError(String error) {
		super(error);
	}
	
	public BASE32FormatError() {
		super();
	}
	
}

