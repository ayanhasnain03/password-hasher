import { MyBcrypt } from "./index";

// src/test.ts

const password = "superSecretPassword";

// Hash the password
const hashedPassword = MyBcrypt.hash(password);
console.log("Hashed Password:", hashedPassword);

// Compare the password
const isMatch = MyBcrypt.compare(password, hashedPassword);
console.log("Password match:", isMatch);
