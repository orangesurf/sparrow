package com.sparrowwallet.sparrow.io.blossom;

import com.sparrowwallet.drongo.policy.Policy;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.Bip39MnemonicCode;
import com.sparrowwallet.drongo.wallet.DeterministicSeed;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;

public class BlossomBackupTest {
    @org.junit.jupiter.api.BeforeAll
    public static void initToolkit() {
        try {
            javafx.application.Platform.startup(() -> {});
        } catch(IllegalStateException e) {
            //Toolkit already initialized
        }
    }

    @Test
    public void deriveKeysDeterministic() throws Exception {
        byte[] entropy = new byte[16];
        new SecureRandom().nextBytes(entropy);
        List<String> words = Bip39MnemonicCode.INSTANCE.toMnemonic(entropy);

        BlossomBackup.BackupKeys keys1 = BlossomBackup.deriveKeys(words);
        BlossomBackup.BackupKeys keys2 = BlossomBackup.deriveKeys(words.stream().map(w -> " " + w.toUpperCase(Locale.ROOT)).toList());

        Assertions.assertArrayEquals(keys1.encryptionKey(), keys2.encryptionKey());
        Assertions.assertArrayEquals(keys1.nostrKey().getPubKeyXCoord(), keys2.nostrKey().getPubKeyXCoord());
    }

    @Test
    public void encryptDecryptRoundTrip() throws Exception {
        byte[] entropy = new byte[16];
        new SecureRandom().nextBytes(entropy);
        List<String> words = Bip39MnemonicCode.INSTANCE.toMnemonic(entropy);
        BlossomBackup.BackupKeys keys = BlossomBackup.deriveKeys(words);

        byte[] data = new byte[4096];
        new SecureRandom().nextBytes(data);
        byte[] payload = BlossomBackup.encrypt(data, keys.encryptionKey());
        Assertions.assertArrayEquals(data, BlossomBackup.decrypt(payload, keys.encryptionKey()));

        byte[] wrongKey = BlossomBackup.deriveKeys(Bip39MnemonicCode.INSTANCE.toMnemonic(new byte[16])).encryptionKey();
        Assertions.assertThrows(Exception.class, () -> BlossomBackup.decrypt(payload, wrongKey));
    }

    @Test
    public void serializeWalletRoundTrip() throws Exception {
        byte[] entropy = new byte[16];
        new SecureRandom().nextBytes(entropy);
        List<String> words = Bip39MnemonicCode.INSTANCE.toMnemonic(entropy);
        DeterministicSeed seed = new DeterministicSeed(words, "", System.currentTimeMillis(), DeterministicSeed.Type.BIP39);

        Wallet wallet = new Wallet("Blossom Backup Test");
        wallet.setPolicyType(PolicyType.SINGLE_HD);
        wallet.setScriptType(ScriptType.P2WPKH);
        wallet.getKeystores().add(Keystore.fromSeed(seed, PolicyType.SINGLE_HD, ScriptType.P2WPKH.getDefaultDerivation()));
        wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD, ScriptType.P2WPKH, wallet.getKeystores(), null));
        Assertions.assertTrue(wallet.isValid());

        BlossomBackup.BackupKeys keys = BlossomBackup.deriveKeys(BlossomBackup.getMnemonicWords(wallet));
        byte[] walletBytes = BlossomBackup.serializeWallet(wallet);
        byte[] payload = BlossomBackup.encrypt(BlossomBackup.packBackup(wallet.getName(), walletBytes), keys.encryptionKey());

        BlossomBackup.Backup backup = BlossomBackup.unpackBackup(BlossomBackup.decrypt(payload, keys.encryptionKey()));
        Wallet restored = BlossomBackup.loadBackupWallet(backup);

        Assertions.assertFalse(restored.isEncrypted());
        Assertions.assertEquals(wallet.getName(), restored.getName());
        Assertions.assertEquals(words, BlossomBackup.getMnemonicWords(restored));

        //Wallet files omit seed-derived public keys; the import flow regenerates them via Storage.restorePublicKeysFromSeed
        Keystore derived = Keystore.fromSeed(restored.getKeystores().get(0).getSeed(), PolicyType.SINGLE_HD, ScriptType.P2WPKH.getDefaultDerivation());
        Assertions.assertEquals(wallet.getKeystores().get(0).getExtendedPublicKey(), derived.getExtendedPublicKey());
    }

    @Test
    @Tag("network")
    public void uploadListDownloadRoundTrip() throws Exception {
        byte[] entropy = new byte[16];
        new SecureRandom().nextBytes(entropy);
        List<String> words = Bip39MnemonicCode.INSTANCE.toMnemonic(entropy);
        BlossomBackup.BackupKeys keys = BlossomBackup.deriveKeys(words);

        byte[] data = new byte[2048];
        new SecureRandom().nextBytes(data);
        byte[] payload = BlossomBackup.encrypt(data, keys.encryptionKey());

        BlossomBackup.BlobDescriptor uploaded = BlossomBackup.upload(keys.nostrKey(), payload);
        Assertions.assertNotNull(uploaded.sha256());

        List<BlossomBackup.BlobDescriptor> blobs = BlossomBackup.list(keys.nostrKey());
        Assertions.assertFalse(blobs.isEmpty());
        Assertions.assertEquals(uploaded.sha256(), blobs.get(0).sha256());

        byte[] downloaded = BlossomBackup.download(keys.nostrKey(), uploaded.sha256());
        Assertions.assertArrayEquals(payload, downloaded);
        Assertions.assertArrayEquals(data, BlossomBackup.decrypt(downloaded, keys.encryptionKey()));
    }
}
