If you don't have Postman already, get it [here](https://www.postman.com/), you can use any tool to send and receive API Requests.
Run the main file and you'll be able to send the following requests:

 POST
```
localhost/7070/generate/<ludp> <--- use one or more of those parameters to modify the generated password (Lower, Upper, Digits, Punctation)
localhost/7070/generate/
localhost/7070/add_password/<email>/<password>
localhost/7070/login/<email>/<password>
localhost/7070/register/<email>/<password>
localhost/7070/add_note/<your_note>
localhost/7070/logout/
localhost/7070/notes/
localhost/7070/passwords/
```
