package org.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.io.*;


public class PasswordVault {

    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()-_=+[]{};:,.<>?/";

    private static final SecureRandom random = new SecureRandom();
    private static final String FILE_NAME = "vault.dat";

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.println("1) Сгенерировать и сохранить пароли");
        System.out.println("2) Расшифровать и показать пароли");
        System.out.print("Выбор: ");
        String mode = sc.nextLine().trim();

        System.out.print("Мастер-пароль: ");
        String master = sc.nextLine();

        if (mode.equals("1")) {
            generateAndSave(sc, master);
        } else if (mode.equals("2")) {
            decryptAndShow(master);
        } else {
            System.out.println("Неизвестный режим.");
        }
    }

    // -------- генерация и сохранение --------

    private static void generateAndSave(Scanner sc, String masterPassword) throws Exception {
        // 1. Пытаемся расшифровать существующий vault.dat
        StringBuilder all = new StringBuilder();
        String previous = tryDecryptExisting(masterPassword);
        if (previous != null && !previous.isEmpty()) {
            all.append(previous);
            if (!previous.endsWith("\n")) {
                all.append("\n");
            }
        }

        // 2. Спрашиваем, сколько НОВЫХ записей добавить
        System.out.print("Сколько новых записей (сайт+логин+пароль) добавить: ");
        int count = Integer.parseInt(sc.nextLine());

        System.out.print("Длина пароля: ");
        int length = Integer.parseInt(sc.nextLine());

        System.out.print("Использовать прописные буквы? (y/n): ");
        boolean useUpper = sc.nextLine().trim().equalsIgnoreCase("y");

        System.out.print("Использовать цифры? (y/n): ");
        boolean useDigits = sc.nextLine().trim().equalsIgnoreCase("y");

        System.out.print("Использовать спецсимволы? (y/n): ");
        boolean useSpecial = sc.nextLine().trim().equalsIgnoreCase("y");

        for (int i = 0; i < count; i++) {
            System.out.println("\n=== Новая запись " + (i + 1) + " ===");
            System.out.print("Сайт/сервис (например, gmail.com): ");
            String site = sc.nextLine().trim();

            System.out.print("Логин/username: ");
            String username = sc.nextLine().trim();

            String password = generatePassword(length, useUpper, useDigits, useSpecial);

            all.append("site: ").append(site).append("\n");
            all.append("user: ").append(username).append("\n");
            all.append("pass: ").append(password).append("\n");
            all.append("----\n");
        }

        String plainText = all.toString();

        // 3. Генерируем новую соль и IV и шифруем ВСЕ записи
        byte[] salt = randomBytes(16);
        byte[] iv = randomBytes(16);
        SecretKey key = deriveKey(masterPassword.toCharArray(), salt);
        byte[] cipherText = encryptAES(plainText.getBytes("UTF-8"), key, iv);

        String saltB64 = Base64.getEncoder().encodeToString(salt);
        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String dataB64 = Base64.getEncoder().encodeToString(cipherText);

        try (PrintWriter out = new PrintWriter(new FileWriter(FILE_NAME))) {
            out.println(saltB64);
            out.println(ivB64);
            out.println(dataB64);
        }

        System.out.println("Записи сохранены (старые + новые) в " + FILE_NAME);
    }

    private static String tryDecryptExisting(String masterPassword) {
        File f = new File(FILE_NAME);
        if (!f.exists()) {
            return "";
        }

        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String saltB64 = br.readLine();
            String ivB64 = br.readLine();
            String dataB64 = br.readLine();

            if (saltB64 == null || ivB64 == null || dataB64 == null) {
                return "";
            }

            byte[] salt = Base64.getDecoder().decode(saltB64);
            byte[] iv = Base64.getDecoder().decode(ivB64);
            byte[] cipherText = Base64.getDecoder().decode(dataB64);

            SecretKey key = deriveKey(masterPassword.toCharArray(), salt);
            byte[] plainBytes = decryptAES(cipherText, key, iv);
            return new String(plainBytes, "UTF-8");
        } catch (Exception e) {
            System.out.println("Не удалось расшифровать существующий vault (возможно, другой мастер-пароль).");
            return "";
        }
    }

    // -------- расшифровка и вывод --------

    private static void decryptAndShow(String masterPassword) throws Exception {
        File f = new File(FILE_NAME);
        if (!f.exists()) {
            System.out.println("Файл " + FILE_NAME + " не найден.");
            return;
        }

        String saltB64;
        String ivB64;
        String dataB64;

        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            saltB64 = br.readLine();
            ivB64 = br.readLine();
            dataB64 = br.readLine();
        }

        if (saltB64 == null || ivB64 == null || dataB64 == null) {
            System.out.println("Файл поврежден или пуст.");
            return;
        }

        byte[] salt = Base64.getDecoder().decode(saltB64);
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] cipherText = Base64.getDecoder().decode(dataB64);

        SecretKey key = deriveKey(masterPassword.toCharArray(), salt);

        try {
            byte[] plainBytes = decryptAES(cipherText, key, iv);
            String plainText = new String(plainBytes, "UTF-8");
            System.out.println("Сохранённые пароли:\n" + plainText);
        } catch (Exception e) {
            System.out.println("Не удалось расшифровать. Возможно, неверный мастер-пароль.");
        }
    }

    // -------- генерация паролей --------

    private static String generatePassword(int length,
                                           boolean useUpper,
                                           boolean useDigits,
                                           boolean useSpecial) {
        StringBuilder alphabet = new StringBuilder(LOWER);
        if (useUpper) alphabet.append(UPPER);
        if (useDigits) alphabet.append(DIGITS);
        if (useSpecial) alphabet.append(SPECIAL);

        if (alphabet.length() == 0) {
            throw new IllegalArgumentException("Нужно выбрать хотя бы один тип символов.");
        }

        StringBuilder password = new StringBuilder();

        if (useUpper) {
            password.append(UPPER.charAt(random.nextInt(UPPER.length())));
        }
        if (useDigits) {
            password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        }
        if (useSpecial) {
            password.append(SPECIAL.charAt(random.nextInt(SPECIAL.length())));
        }

        while (password.length() < length) {
            int idx = random.nextInt(alphabet.length());
            password.append(alphabet.charAt(idx));
        }

        return shuffle(password.toString());
    }

    private static String shuffle(String input) {
        char[] arr = input.toCharArray();
        for (int i = arr.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }
        return new String(arr);
    }

    // -------- крипто-утилиты --------

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }

    // PBKDF2WithHmacSHA256 -> ключ 256 бит для AES
    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        int iterations = 65536;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encryptAES(byte[] plain, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plain);
    }

    private static byte[] decryptAES(byte[] cipherText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }
}
