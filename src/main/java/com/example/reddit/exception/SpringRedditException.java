package com.example.reddit.exception;

import org.springframework.mail.MailException;

public class SpringRedditException extends RuntimeException {
    public SpringRedditException(String s) {
        super(s);
    }
}
