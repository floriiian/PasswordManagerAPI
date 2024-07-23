package de.florian.passwordmanager;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Note {

    public String note;
    public String creation_time;

    public Note(String note) {
        this.note = note;

        LocalDateTime DateObject = LocalDateTime.now();
        DateTimeFormatter FormatObject = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        this.creation_time = DateObject.format(FormatObject);
    }
}
