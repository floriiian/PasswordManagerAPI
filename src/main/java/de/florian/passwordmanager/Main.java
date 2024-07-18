package de.florian.passwordmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.http.BadRequestResponse;
import io.javalin.plugin.bundled.CorsPluginConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.javalin.Javalin;
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

    public static ArrayList<Account> accounts = new ArrayList<Account>();

    public static void main(String[] args) throws NoSuchAlgorithmException {

        Javalin app = Javalin.create(config -> {
            config.bundledPlugins.enableCors(cors -> {
                cors.addRule(CorsPluginConfig.CorsRule::anyHost);
            });
        }).start(7070);

        app.post("/register", _ -> {
            throw new BadRequestResponse("Insufficient credentials");
        });
        app.post("/login", _ -> {
            throw new BadRequestResponse("Insufficient credentials");
        });

        app.post("/logout", ctx -> {
            ctx.cookieStore().clear();
            ctx.result("LOGGED_OUT");
            ctx.status(200);
        });


        app.post("/register/<email>/<password>", ctx -> {
            ctx.result(addAccount(ctx.pathParam("email"), ctx.pathParam("password")));
        });
        app.post("/login/<email>/<password>", ctx -> {
            String functionResponse = handleLogin(ctx.pathParam("email"), ctx.pathParam("password"));
            String response = functionResponse.split(":")[0].strip();
            String sessionKey = functionResponse.split(":")[1].strip();

            ctx.result(response);
            if(response.equals("SUCCESSFUL_LOGIN")){
                ctx.cookieStore().set("sessionKey", sessionKey);
                LOGGER.debug("User {} logged in", ctx.pathParam("email"));
            }
        });
    }

    public static String handleLogin(String email, String password) throws NoSuchAlgorithmException {

        if (email == null || password == null){
            return "CREDENTIALS_NULL : ";
        }
        if (email.isEmpty() ||password.isEmpty()){
            return "CREDENTIALS_EMPTY : ";
        }
        for (Account account : accounts){
            if (account.email.equals(email) && encoder().matches(password, account.password)){

                byte[] key = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(key);
                String base64Key = Base64.getEncoder().encodeToString(key);
                account.sessionKey = base64Key;

                return "SUCCESSFUL_LOGIN : " + base64Key;
            }
        }
        return "CREDENTIALS_INVALID : ";
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

    public static PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }




}