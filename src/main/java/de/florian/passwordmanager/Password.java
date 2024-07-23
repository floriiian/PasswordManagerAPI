package de.florian.passwordmanager;

import java.util.Date;

public class Password {

    public String username;
    public String password;
    public String website;
    public Date creation_time;

    public Password(String username, String password, String website) {
        this.username = username;
        this.password = password;
        this.website = website;
        this.creation_time = new Date();
    }
}
