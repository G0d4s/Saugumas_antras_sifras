package org.example;

import java.util.Scanner;
import java.io.IOException;
import java.io.BufferedWriter;
import java.io.FileWriter;


public class Main {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);


        // Get the plaintext from the user
        System.out.print("Enter the plaintext: ");
        String plaintext = scanner.nextLine();


        // Get the encryption/decryption function from the user
        System.out.println("Select a mode:");
        System.out.println("1. ECB");
        System.out.println("2. CBC");
        System.out.println("3. CFB");
        System.out.println("4. OFB");
        System.out.println("5. CTR");
        int mode = scanner.nextInt();
        scanner.nextLine(); // consume leftover newline character

        // Get the secret key from the user
        System.out.print("Enter the secret key: ");//2345678901234567
        String secretKey = scanner.nextLine();


        // Declare an IV variable for CBC mode
        String iv = null;


        // Encrypt or decrypt the plaintext based on the user's selection
        String result = "";
        switch (mode) {
            case 1:
                result = AES.encryptECB(plaintext, secretKey);
                break;

            case 2:
                // Prompt the user to enter the IV
                System.out.print("Enter the IV (must be 16 bytes long): ");
                iv = scanner.next();
                result = AES.encryptCBC(plaintext, secretKey, iv);
                break;
            case 3:
                // Prompt the user to enter the IV
                System.out.print("Enter the IV (must be 16 bytes long): ");
                iv = scanner.next();
                result = AES.encryptCFB(plaintext, secretKey, iv);
                break;
            case 4:
                // Prompt the user to enter the IV
                System.out.print("Enter the IV (must be 16 bytes long): ");
                iv = scanner.next();
                result = AES.encryptOFB(plaintext, secretKey, iv);
                break;
            case 5:
                // Prompt the user to enter the IV
                System.out.print("Enter the IV (must be 16 bytes long): ");
                iv = scanner.next();
                result = AES.encryptCTR(plaintext, secretKey, iv);
                break;
            default:
                System.out.println("Invalid mode selection.");
                return;

        }

        // Prompt the user to enter a filename to save the encrypted text to
        System.out.print("Enter the filename to save the encrypted text to: ");
        String filename = scanner.next();

        // Save the encrypted text to the specified file
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
            writer.write(result);
            writer.close();
            System.out.println("Encryption successful. Ciphertext saved to " + filename);
        } catch (IOException e) {
            System.out.println("Error writing to file: " + e.getMessage());
        }

        // Print the result
        System.out.println("Result: " + result);

        //if wants to decrypt the ciphertext in ECB mode
        if (mode == 1) {
            System.out.println("Do you want to decrypt ciphertext?(yes/no)");
            String choice = scanner.next();
            if (choice.equalsIgnoreCase("yes")) {
                //Decrypt the ciphertext
                String decrypted = AES.decryptECB(result, secretKey);
                System.out.println("Decrypted plaintext: " + decrypted);
            }
        }

        //Prompt the user to decrypt the ciphertext if in CBC mode
        if (mode == 2) {
            System.out.println("Do you want to decrypt the ciphertext? (yes/no)");
            String choice = scanner.next();
            if (choice.equalsIgnoreCase("yes")) {
                // Decrypt the ciphertext
                String decrypted = AES.decryptCBC(result, secretKey, iv);
                System.out.println("Decrypted plaintext: " + decrypted);
            }
        }

        if (mode == 3) {
            System.out.println("Do you want to decrypt the ciphertext? (yes/no)");
            String choice = scanner.next();
            if (choice.equalsIgnoreCase("yes")) {
                // Decrypt the ciphertext
                String decrypted = AES.decryptCFB(result, secretKey, iv);
                System.out.println("Decrypted plaintext: " + decrypted);
            }
        }

        if (mode == 4) {
            System.out.println("Do you want to decrypt the ciphertext? (yes/no)");
            String choice = scanner.next();
            if (choice.equalsIgnoreCase("yes")) {
                // Decrypt the ciphertext
                String decrypted = AES.decryptOFB(result, secretKey, iv);
                System.out.println("Decrypted plaintext: " + decrypted);
            }
        }

        if (mode == 5) {
            System.out.println("Do you want to decrypt the ciphertext? (yes/no)");
            String choice = scanner.next();
            if (choice.equalsIgnoreCase("yes")) {
                // Decrypt the ciphertext
                String decrypted = AES.decryptCTR(result, secretKey, iv);
                System.out.println("Decrypted plaintext: " + decrypted);
            }
        }
    }
}

