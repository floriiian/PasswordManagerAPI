package de.florian.passwordmanager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.http.BadRequestResponse;
import io.javalin.plugin.bundled.CorsPluginConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.javalin.Javalin;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    public static void main(String[] args) {

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

        app.post("/register/<email>/<password>", ctx -> {
            ctx.result(addAccount(ctx.pathParam("email"), ctx.pathParam("password")));
        });
        app.post("/login/<email>/<password>", ctx -> {
            ctx.result(addAccount(ctx.pathParam("email"), ctx.pathParam("password")));
        });

    }


    public static String handleLogin(String email, String password){

        if (email == null || password == null){
            return "CREDENTIALS_NULL";
        }
        if (email.isEmpty() ||password.isEmpty()){
            return "CREDENTIALS_EMPTY";
        }
        for (Account account : accounts){
            if (account.email.equals(email) && account.password.equals(password)){

            }
        }
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

    public static generateSessionKey(){

    }

    public static PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }




}