package git.github.hydroque.JOTP;

public class HMACGenerationError extends RuntimeException {
	
	public HMACGenerationError(String error) {
		super(error);
	}
	
	public HMACGenerationError() {
		super();
	}
	
}

