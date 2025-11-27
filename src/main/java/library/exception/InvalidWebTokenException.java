package library.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidWebTokenException extends RuntimeException {

    public InvalidWebTokenException(String message) {
        super(message);
    }

    public InvalidWebTokenException(String message, Throwable e) {
        super(message, e);
    }
}
