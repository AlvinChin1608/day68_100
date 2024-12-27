What I Learned Today: Password Salting and Hashing with Flask
In my Flask application, I worked on enhancing user authentication security by adding password salting and hashing. Here’s what I learned:

Password Hashing:

Storing passwords as plain text is dangerous because anyone who gains access to the database can read them.
The generate_password_hash() function from werkzeug.security is used to hash a password before storing it in the database, making it more secure.
It is important to choose a strong hashing algorithm, and werkzeug.security provides PBKDF2 hashing by default, which is a good choice.
Salting:

Salting adds a random string to the password before hashing it. This helps protect against rainbow table attacks, where precomputed hash values are used to reverse engineer passwords.
I generated a random salt using Python’s os.urandom() function. The salt is then appended to the password before it is hashed. The salt itself is stored in the database alongside the password hash.
The salt ensures that even if two users have the same password, their hashes will be different, as each will have a unique salt value.
Database Storage:

The hashed password and the salt are stored in the database separately. This allows us to compare the entered password during login with the stored hash by applying the same salt.
I updated the User model in the database to include a salt column to store the generated salt.
Login Process:

During login, I combine the entered password with the stored salt, and then hash the resulting string. The hashed result is compared with the stored password hash in the database using check_password_hash().
If the hashes match, the user is authenticated and logged in.
Security Benefits:

Salting makes it harder for attackers to crack passwords even if they have access to the hashed password database.
Combining salting with hashing ensures that passwords are stored securely, mitigating the risk of password breaches.