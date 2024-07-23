package de.florian.passwordmanager;

import java.util.ArrayList;

public class Account {

    public String email;
    public String password;
    public int accountId;
    public ArrayList<Note> notes = new ArrayList<>();
    public ArrayList<Password > passwords = new ArrayList<>();
    public String sessionKey;


    public Account(String email, String password, int accountId) {
        this.email = email;
        this.password = password;
        this.accountId = accountId;
    }

    public void addNote(Note note) {
        notes.add(note);
    }

    public void addPassword(String email, String password,String website) {
        passwords.add(new Password(email, password, website));
    }
}
