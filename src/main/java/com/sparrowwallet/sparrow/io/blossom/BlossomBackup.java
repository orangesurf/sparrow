package com.sparrowwallet.sparrow.io.blossom;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.crypto.SchnorrSignature;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.Bip39MnemonicCode;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.sparrow.io.Persistence;
import com.sparrowwallet.sparrow.io.PersistenceType;
import com.sparrowwallet.sparrow.io.Storage;
import com.sparrowwallet.sparrow.io.StorageException;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Encrypted wallet backup to a Blossom server (BUD-01/BUD-02), where both the encryption key
 * and the nostr identity used to store and retrieve the blob are derived deterministically from
 * the wallet's BIP39 mnemonic. A backup can therefore be created and later recovered with
 * nothing but the seed words.
 *
 * Derivation: ikm = BIP39 seed (empty passphrase), then HKDF-SHA256 with a fixed salt yields
 * a 256-bit AES-GCM key (info "v1/aes-key") and a secp256k1 private key (info "v1/nostr-key").
 * The blob is the gzipped, unencrypted Sparrow wallet file encrypted with AES-256-GCM.
 */
public class BlossomBackup {
    private static final Logger log = LoggerFactory.getLogger(BlossomBackup.class);

    public static final String SERVER = "https://blossom.primal.net";

    private static final byte[] HKDF_SALT = "sparrow-blossom-backup".getBytes(StandardCharsets.UTF_8);
    private static final String AES_KEY_INFO = "v1/aes-key";
    private static final String NOSTR_KEY_INFO = "v1/nostr-key";
    private static final byte[] PAYLOAD_MAGIC = new byte[]{'S', 'B', 'B', '1'};
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int AUTH_EVENT_KIND = 24242;
    private static final long AUTH_EVENT_EXPIRY_SECS = 600;

    private static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    public record BackupKeys(byte[] encryptionKey, ECKey nostrKey) {}

    public record BlobDescriptor(String sha256, long size, long uploaded, String url) {}

    public record Backup(String walletName, byte[] walletBytes) {}

    public static byte[] packBackup(String walletName, byte[] walletBytes) throws IOException {
        byte[] nameBytes = walletName.getBytes(StandardCharsets.UTF_8);
        if(nameBytes.length > 0xFFFF) {
            throw new IOException("Wallet name too long");
        }
        ByteArrayOutputStream packed = new ByteArrayOutputStream();
        packed.write(nameBytes.length >> 8);
        packed.write(nameBytes.length & 0xFF);
        packed.write(nameBytes);
        packed.write(walletBytes);
        return packed.toByteArray();
    }

    public static Backup unpackBackup(byte[] plaintext) throws IOException {
        if(plaintext.length < 2) {
            throw new IOException("Backup payload too short");
        }
        int nameLength = ((plaintext[0] & 0xFF) << 8) | (plaintext[1] & 0xFF);
        if(plaintext.length < 2 + nameLength) {
            throw new IOException("Backup payload too short");
        }
        String walletName = new String(plaintext, 2, nameLength, StandardCharsets.UTF_8);
        return new Backup(walletName, Arrays.copyOfRange(plaintext, 2 + nameLength, plaintext.length));
    }

    public static BackupKeys deriveKeys(List<String> mnemonicWords) {
        List<String> normalized = mnemonicWords.stream().map(word -> word.trim().toLowerCase(Locale.ROOT)).toList();
        byte[] ikm = Bip39MnemonicCode.toSeed(normalized, "");
        byte[] encryptionKey = hkdfSha256(ikm, HKDF_SALT, AES_KEY_INFO.getBytes(StandardCharsets.UTF_8), 32);
        byte[] nostrPrivKey = hkdfSha256(ikm, HKDF_SALT, NOSTR_KEY_INFO.getBytes(StandardCharsets.UTF_8), 32);
        Arrays.fill(ikm, (byte)0);
        return new BackupKeys(encryptionKey, ECKey.fromPrivate(nostrPrivKey));
    }

    public static List<String> getMnemonicWords(Wallet decryptedWallet) {
        return decryptedWallet.getKeystores().stream()
                .filter(Keystore::hasSeed)
                .map(keystore -> keystore.getSeed().getMnemonicCode())
                .filter(Objects::nonNull)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Wallet does not contain a BIP39 seed"));
    }

    public static byte[] serializeWallet(Wallet decryptedWallet) throws IOException, StorageException {
        PersistenceType persistenceType = PersistenceType.DB;
        Persistence persistence = persistenceType.getInstance();
        File tempFile = File.createTempFile("sparrowbackup", "." + persistenceType.getExtension());
        tempFile.delete();
        Storage tempStorage = new Storage(persistence, tempFile);
        tempStorage.setEncryptionPubKey(Storage.NO_PASSWORD_KEY);
        tempStorage.saveWallet(decryptedWallet);
        for(Wallet childWallet : decryptedWallet.getChildWallets()) {
            tempStorage.saveWallet(childWallet);
        }
        persistence.close();
        byte[] walletBytes = Files.readAllBytes(tempStorage.getWalletFile().toPath());
        tempStorage.getWalletFile().delete();
        return walletBytes;
    }

    public static byte[] encrypt(byte[] plaintext, byte[] encryptionKey) throws IOException, GeneralSecurityException {
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try(GZIPOutputStream gzip = new GZIPOutputStream(compressed)) {
            gzip.write(plaintext);
        }

        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
        cipher.updateAAD(PAYLOAD_MAGIC);
        byte[] ciphertext = cipher.doFinal(compressed.toByteArray());

        ByteArrayOutputStream payload = new ByteArrayOutputStream();
        payload.write(PAYLOAD_MAGIC);
        payload.write(nonce);
        payload.write(ciphertext);
        return payload.toByteArray();
    }

    public static byte[] decrypt(byte[] payload, byte[] encryptionKey) throws IOException, GeneralSecurityException {
        if(payload.length < PAYLOAD_MAGIC.length + GCM_NONCE_LENGTH + 16
                || !Arrays.equals(Arrays.copyOfRange(payload, 0, PAYLOAD_MAGIC.length), PAYLOAD_MAGIC)) {
            throw new IOException("Not a Sparrow encrypted backup payload");
        }

        byte[] nonce = Arrays.copyOfRange(payload, PAYLOAD_MAGIC.length, PAYLOAD_MAGIC.length + GCM_NONCE_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encryptionKey, "AES"), new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
        cipher.updateAAD(PAYLOAD_MAGIC);
        byte[] compressed = cipher.doFinal(payload, PAYLOAD_MAGIC.length + GCM_NONCE_LENGTH, payload.length - PAYLOAD_MAGIC.length - GCM_NONCE_LENGTH);

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        try(GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
            gzip.transferTo(plaintext);
        }
        return plaintext.toByteArray();
    }

    public static BlobDescriptor upload(ECKey nostrKey, byte[] blob) throws IOException, InterruptedException {
        String sha256Hex = Utils.bytesToHex(Sha256Hash.of(blob).getBytes());
        HttpRequest request = HttpRequest.newBuilder(URI.create(SERVER + "/upload"))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(blob))
                .header("Authorization", authorization(nostrKey, "upload", sha256Hex))
                .header("Content-Type", "application/octet-stream")
                .timeout(Duration.ofMinutes(2))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if(response.statusCode() != 200) {
            throw new IOException("Upload to " + SERVER + " failed with HTTP " + response.statusCode() + ": " + response.body());
        }
        return gson.fromJson(response.body(), BlobDescriptor.class);
    }

    public static List<BlobDescriptor> list(ECKey nostrKey) throws IOException, InterruptedException {
        String pubkey = Utils.bytesToHex(nostrKey.getPubKeyXCoord());
        HttpRequest request = HttpRequest.newBuilder(URI.create(SERVER + "/list/" + pubkey))
                .GET()
                .header("Authorization", authorization(nostrKey, "list", null))
                .timeout(Duration.ofMinutes(1))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if(response.statusCode() != 200) {
            throw new IOException("Listing backups on " + SERVER + " failed with HTTP " + response.statusCode() + ": " + response.body());
        }
        List<BlobDescriptor> blobs = new ArrayList<>(Arrays.asList(gson.fromJson(response.body(), BlobDescriptor[].class)));
        blobs.sort(Comparator.comparingLong(BlobDescriptor::uploaded).reversed());
        return blobs;
    }

    public static byte[] download(ECKey nostrKey, String sha256Hex) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(SERVER + "/" + sha256Hex))
                .GET()
                .header("Authorization", authorization(nostrKey, "get", sha256Hex))
                .timeout(Duration.ofMinutes(2))
                .build();
        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if(response.statusCode() != 200) {
            throw new IOException("Downloading backup from " + SERVER + " failed with HTTP " + response.statusCode());
        }
        return response.body();
    }

    public static Wallet loadBackupWallet(Backup backup) throws IOException, StorageException {
        File tempDir = Files.createTempDirectory("sparrowrestore").toFile();
        String fileName = backup.walletName().isEmpty() ? "Restored Wallet" : backup.walletName().replaceAll("[/\\\\:]", "_");
        File walletFile = new File(tempDir, fileName + "." + PersistenceType.DB.getExtension());
        Files.write(walletFile.toPath(), backup.walletBytes());
        Storage storage = new Storage(PersistenceType.DB, walletFile);
        try {
            Wallet wallet = storage.loadUnencryptedWallet().getWallet();
            wallet.setName(fileName);
            return wallet;
        } finally {
            storage.close();
            walletFile.delete();
            tempDir.delete();
        }
    }

    private static String authorization(ECKey nostrKey, String verb, String sha256Hex) {
        String pubkey = Utils.bytesToHex(nostrKey.getPubKeyXCoord());
        long createdAt = System.currentTimeMillis() / 1000;
        List<List<String>> tags = new ArrayList<>();
        tags.add(List.of("t", verb));
        if(sha256Hex != null) {
            tags.add(List.of("x", sha256Hex));
        }
        tags.add(List.of("expiration", Long.toString(createdAt + AUTH_EVENT_EXPIRY_SECS)));
        String content = verb + " wallet backup";

        String canonical = gson.toJson(List.of(0, pubkey, createdAt, AUTH_EVENT_KIND, tags, content));
        Sha256Hash eventId = Sha256Hash.of(canonical.getBytes(StandardCharsets.UTF_8));
        SchnorrSignature signature = nostrKey.signSchnorr(eventId);

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("id", Utils.bytesToHex(eventId.getBytes()));
        event.put("pubkey", pubkey);
        event.put("created_at", createdAt);
        event.put("kind", AUTH_EVENT_KIND);
        event.put("tags", tags);
        event.put("content", content);
        event.put("sig", Utils.bytesToHex(signature.encode()));
        return "Nostr " + Base64.getEncoder().encodeToString(gson.toJson(event).getBytes(StandardCharsets.UTF_8));
    }

    public static class BackupService extends Service<BlobDescriptor> {
        private final Wallet decryptedWallet;

        public BackupService(Wallet decryptedWallet) {
            this.decryptedWallet = decryptedWallet;
        }

        @Override
        protected Task<BlobDescriptor> createTask() {
            return new Task<>() {
                @Override
                protected BlobDescriptor call() throws Exception {
                    List<String> mnemonicWords = getMnemonicWords(decryptedWallet);
                    BackupKeys keys = deriveKeys(mnemonicWords);
                    byte[] walletBytes = serializeWallet(decryptedWallet);
                    byte[] payload = encrypt(packBackup(decryptedWallet.getName(), walletBytes), keys.encryptionKey());
                    Arrays.fill(keys.encryptionKey(), (byte)0);
                    return upload(keys.nostrKey(), payload);
                }
            };
        }
    }

    public static class RestoreService extends Service<Wallet> {
        private final List<String> mnemonicWords;

        public RestoreService(List<String> mnemonicWords) {
            this.mnemonicWords = mnemonicWords;
        }

        @Override
        protected Task<Wallet> createTask() {
            return new Task<>() {
                @Override
                protected Wallet call() throws Exception {
                    BackupKeys keys = deriveKeys(mnemonicWords);
                    List<BlobDescriptor> blobs = list(keys.nostrKey());
                    if(blobs.isEmpty()) {
                        throw new IOException("No backups found on " + SERVER + " for this seed");
                    }

                    Exception lastException = null;
                    for(BlobDescriptor blob : blobs) {
                        try {
                            byte[] payload = download(keys.nostrKey(), blob.sha256());
                            Backup backup = unpackBackup(decrypt(payload, keys.encryptionKey()));
                            return loadBackupWallet(backup);
                        } catch(Exception e) {
                            log.warn("Could not restore backup blob " + blob.sha256() + ", trying next", e);
                            lastException = e;
                        }
                    }

                    throw new IOException("Found " + blobs.size() + " backup blob(s) on " + SERVER + " but none could be decrypted and restored", lastException);
                }
            };
        }
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            ByteArrayOutputStream okm = new ByteArrayOutputStream();
            byte[] previous = new byte[0];
            for(byte counter = 1; okm.size() < length; counter++) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(previous);
                mac.update(info);
                mac.update(counter);
                previous = mac.doFinal();
                okm.write(previous, 0, previous.length);
            }
            return Arrays.copyOf(okm.toByteArray(), length);
        } catch(GeneralSecurityException e) {
            throw new IllegalStateException("HKDF-SHA256 unavailable", e);
        }
    }
}
