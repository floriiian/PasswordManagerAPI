package de.florian.passwordmanager;

import java.util.ArrayList;

public class Account {

    public String email;
    public String password;
    public int accountId;
    public ArrayList<String> notes = new ArrayList<>();
    public ArrayList<String[] > passwords = new ArrayList<>();


    public Account(String email, String password, int accountId) {
        this.email = email;
        this.password = password;
        this.accountId = accountId;
    }

    public void addNote(String note) {
        notes.add(note);
    }

    public void addPassword(String email, String password) {
        passwords.add(new String[]{email, password});
    }
}
