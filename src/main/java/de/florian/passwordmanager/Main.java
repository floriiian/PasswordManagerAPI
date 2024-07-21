package de.florian.passwordmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.plugin.bundled.CorsPluginConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import jakarta.servlet.http.Cookie;

import io.javalin.Javalin;
import org.json.JSONObject;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;


public class Main {

    public static final Logger LOGGER = LogManager.getLogger();
    public static final ObjectMapper MAPPER = new ObjectMapper();

    public static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$");
    public static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String PUNCTUATION = "!@#$%&*()_+-=[]|,./?><";

    public static String[] staticSites = {"/register", "/login", "/add_password", "/"};
    public static ArrayList<Account> accounts = new ArrayList<>();

    public static void main(String[] args) throws NoSuchAlgorithmException {

        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(CorsPluginConfig.CorsRule::anyHost);
            });
        }).start(7070);

        for (String site : staticSites) {
            app.post(site, _ ->  {
                throw new BadRequestResponse("Insufficient credentials");
            });
        }

        app.post("/generate/<parameters>", ctx -> {
            String result = generatePassword(ctx.pathParam("parameters"));
            if (result.isEmpty()){
                JSONObject response = new JSONObject();
                response.put("ERROR_TYPE","INVALID_PARAMETER").put("ERROR_MESSAGE","Available parameters: l,u,d,p");
                ctx.result(String.valueOf(response));
                return;
            }
            ctx.result(result);
        });

        app.post("/generate", ctx -> {
            ctx.result(generatePassword("ludp"));
        });

        app.post("/passwords", ctx -> {
            String id = ctx.cookie("id");
            if (isLoggedIn(ctx)) {
                if (id != null) {
                    ctx.result(getPasswords(Integer.parseInt(id)));
                    return;
                }
            }
            ctx.result("NOT_LOGGED_IN");
        });

        app.post("/notes", ctx -> {
            if (isLoggedIn(ctx)){
                String id = ctx.cookie("id");
                if (id != null) {
                    ctx.result(getNotes(Integer.parseInt(id)));
                    return;
                }
            }
            ctx.result("NOT_LOGGED_IN");
        });

        app.post("/add_password/<email>/<password>", ctx -> {
            if (isLoggedIn(ctx)){
                String id = ctx.cookie("id");
                if (id != null) {
                    ctx.result(addPassword(ctx.pathParam("email"), ctx.pathParam("password"), Integer.valueOf(id)));
                    return;
                }
            }
            ctx.result("NOT_LOGGED_IN");
        });

        app.post("/add_note/<note>", ctx -> {
            if (isLoggedIn(ctx)){
                String id = ctx.cookie("id");
                if (id != null) {
                    ctx.result(addNote(ctx.pathParam("note"), Integer.valueOf(id)));
                    return;
                }
            }
            ctx.result("NOT_LOGGED_IN");
        });

        app.post("/register/<email>/<password>", ctx -> {
            ctx.result(addAccount(ctx.pathParam("email"), ctx.pathParam("password")));
        });

        app.post("/login/<email>/<password>", ctx -> {
            if (isLoggedIn(ctx)){
                ctx.result("ALREADY_LOGGED_IN");
                return;
            }

            String[] functionResponse = handleLogin(ctx.pathParam("email"), ctx.pathParam("password")).split(":");

            String response = functionResponse[0].strip();
            String sessionKey = functionResponse[1].strip();
            String id = functionResponse[2].strip();

            if (response.equals("SUCCESSFUL_LOGIN")){

                Cookie sessionKeyCookie = new Cookie("sessionKey", sessionKey);
                sessionKeyCookie.setHttpOnly(true);
                sessionKeyCookie.setSecure(true);
                sessionKeyCookie.setPath("/");

                Cookie idCookie = new Cookie("id", id);
                idCookie.setHttpOnly(true);
                idCookie.setSecure(true);
                idCookie.setPath("/");

                ctx.res().addCookie(sessionKeyCookie);
                ctx.res().addCookie(idCookie);

                LOGGER.debug("User {} logged in", ctx.pathParam("email"));
            }
            ctx.result(response);
        });

        app.post("/logout", ctx -> {
            String sessionKey = ctx.cookie("sessionKey");

            if (sessionKey == null){
                return;
            }
            if (sessionKey.length() > 1) {
                for (Account account : accounts) {
                    if (account.sessionKey.equals(sessionKey)){
                        account.sessionKey = "";
                    }
                }
            }

            Cookie sessionKeyCookie = new Cookie("sessionKey", null);
            sessionKeyCookie.setMaxAge(0);
            ctx.res().addCookie(sessionKeyCookie);

            Cookie idCookie = new Cookie("id", null);
            idCookie.setMaxAge(0);
            ctx.res().addCookie(idCookie);

            ctx.result("LOGGED_OUT");
            ctx.status(200);
        });
    }

    private static boolean isLoggedIn(Context ctx) {
        String sessionKey = ctx.cookie("sessionKey");
        String id = ctx.cookie("id");

        if (sessionKey != null && sessionKey.length() > 1 && id != null && !id.isEmpty()) {
            for (Account account : accounts) {
                if (account.sessionKey != null && account.sessionKey.equals(sessionKey)) {
                    ctx.attribute("accountId", Integer.parseInt(id));
                    return true;
                }
            }
        }
        return false;
    }

    public static String getPasswords(int id){
        JSONObject passwords = new JSONObject();#
        for (Account account : accounts) {
            if (account.accountId == id){
                for (String[] password : account.passwords ){
                    passwords.put(password[0], password[1]);
                }
            }
        }
        return passwords.toString();
    }


    public static String getNotes(int id){
        JSONObject notes = new JSONObject();
        for (Account account : accounts) {
            if (account.accountId == id){
                int i = 1;
                for (String note : account.notes ){
                    notes.put(String.valueOf(i), note);
                    i++;
                }
            }
        }
        return notes.toString();
    }

    public static String addNote(String note, Integer id){
        if (note == null || note.isEmpty() ){
            return "INPUT_EMPTY";
        }
        for (Account account : accounts) {
            if (account.accountId == id){
                account.notes.add(note);
                return "SUCCESSFUL_INSERT";
            }
        }
        return "ERROR_INSERTING";
    }

    public static String addPassword(String email, String password, Integer id) {
        if (email == null || password == null || email.isEmpty() || password.isEmpty()){
            return "INPUT_EMPTY";
        }
        for (Account account : accounts) {
            if (account.accountId == id){
                account.passwords.add(new String[]{email, password});
                return "SUCCESSFUL_INSERT";
            }
        }
        return "ERROR_INSERTING";
    }


    public static String handleLogin(String email, String password) throws NoSuchAlgorithmException {

        if (email == null || password == null){
            return "CREDENTIALS_NULL : : ";
        }
        if (email.isEmpty() ||password.isEmpty()){
            return "CREDENTIALS_EMPTY : : ";
        }
        for (Account account : accounts){
            if (account.email.equals(email) && encoder().matches(password, account.password)){

                int id = account.accountId;
                byte[] key = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(key);
                String base64Key = Base64.getEncoder().encodeToString(key);
                account.sessionKey = base64Key;

                return "SUCCESSFUL_LOGIN:" + base64Key + ":" + id;
            }
        }
        return "CREDENTIALS_INVALID : : ";
    }


    public static String addAccount(String email, String password){
        if (email == null || password == null){
            return "CREDENTIALS_NULL";
        }
        if (email.isEmpty() ||password.isEmpty()){
            return "CREDENTIALS_EMPTY";
        }
        if (!EMAIL_PATTERN.matcher(email).matches()){
            return "INVALID_EMAIL";
        }
        if (!PASSWORD_PATTERN.matcher(password).matches()){
            return "WEAK_PASSWORD";
        }

        Account newAccount = new Account(email, encoder().encode(password), accounts.size() + 1);
        accounts.add(newAccount);
        LOGGER.debug("Account added with ID: {}", newAccount.accountId);
        return "SUCCESSFUL_REGISTRATION {" + newAccount.accountId + "}";
    }

    public static String generatePassword(String parameters){

        int passwordLength = new Random().nextInt((20 - 10) + 1) + 10;
        String password = "";
        StringBuilder allowedChars = new StringBuilder();

        if (parameters.toLowerCase().contains("l")) {
            allowedChars.append(LOWER);
        }
        if (parameters.toLowerCase().contains("u")) {
            allowedChars.append(UPPER);
        }
        if (parameters.toLowerCase().contains("d")) {
            allowedChars.append(DIGITS);
        }
        if (parameters.toLowerCase().contains("p")) {
            allowedChars.append(PUNCTUATION);
        }

        if(allowedChars.isEmpty()){
            return "";
        }

        Random random = new Random();
        while (password.length() < passwordLength){
            password = password.concat(String.valueOf(allowedChars.charAt(random.nextInt(allowedChars.length()))));
        }
        return password;
    }

    public static PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}