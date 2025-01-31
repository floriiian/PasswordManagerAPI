package de.florian.passwordmanager;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Password {

    public String username;
    public String password;
    public String website;
    public String creation_time;

    public Password(String username, String password, String website) {
        this.username = username;
        this.password = password;
        this.website = website;

        LocalDateTime DateObject = LocalDateTime.now();
        DateTimeFormatter FormatObject = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        this.creation_time = DateObject.format(FormatObject);
    }
}
