# What I Learned Today: Password Salting and Hashing with Flask

In my Flask application, I worked on enhancing user authentication security by adding password salting and hashing. Here’s what I learned:

1. __Password Hashing:__
  - Storing passwords as plain text is dangerous because anyone who gains access to the database can read them.
  - The generate_password_hash() function from werkzeug.security is used to hash a password before storing it in the database, making it more secure.
  - It is important to choose a strong hashing algorithm, and werkzeug.security provides PBKDF2 hashing by default, which is a good choice.

2. __Salting:__
  - Salting adds a random string to the password before hashing it. This helps protect against rainbow table attacks, where precomputed hash values are used to reverse engineer passwords.
  - I generated a random salt using Python’s os.urandom() function. The salt is then appended to the password before it is hashed. The salt itself is stored in the database alongside the password hash.
  - The salt ensures that even if two users have the same password, their hashes will be different, as each will have a unique salt value.

3. __Database Storage:__

  - The hashed password and the salt are stored in the database separately. This allows us to compare the entered password during login with the stored hash by applying the same salt.
  - I updated the User model in the database to include a salt column to store the generated salt.

4. __Login Process:__
  - During login, I combine the entered password with the stored salt, and then hash the resulting string. The hashed result is compared with the stored password hash in the database using check_password_hash().
  - If the hashes match, the user is authenticated and logged in.

5. __Security Benefits:__

  - Salting makes it harder for attackers to crack passwords even if they have access to the hashed password database.
  - Combining salting with hashing ensures that passwords are stored securely, mitigating the risk of password breaches.

### Login
![](https://github.com/AlvinChin1608/day68_100/blob/main/gif_demo/demo_login.gif)

### Database of registered user
![](https://github.com/AlvinChin1608/day68_100/blob/main/gif_demo/demo_credential.png)

### Email already exist
![](https://github.com/AlvinChin1608/day68_100/blob/main/gif_demo/ScreenRecording2024-12-30at14.58.40-ezgif.com-video-to-gif-converter.gif)

### Invalid password or email
![](https://github.com/AlvinChin1608/day68_100/blob/main/gif_demo/ScreenRecording2024-12-30at14.48.43-ezgif.com-video-to-gif-converter.gif)
