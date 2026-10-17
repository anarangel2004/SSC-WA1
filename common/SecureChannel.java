package common;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

// Canal seguro de uma sessão: ECDH -> chave de sessão K -> AES-GCM
public class SecureChannel {

    private final CryptoConfig cfg;
    private final KeyPair myKeys;     // par ECDH novo em cada sessão
    private SecretKeySpec k;          // chave de sessão K

    public SecureChannel(CryptoConfig cfg) throws Exception {
        this.cfg = cfg;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));   // curva P-256
        myKeys = kpg.generateKeyPair();
    }

    // Chave pública a enviar ao outro lado
    public byte[] myPublicKey() {
        return myKeys.getPublic().getEncoded();
    }

    // ECDH com a chave pública do outro lado e K = SHA-256(segredo || SKey)
    public void computeKey(byte[] otherPublicKey) throws Exception {
        PublicKey other = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(otherPublicKey));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myKeys.getPrivate());
        ka.doPhase(other, true);
        byte[] secret = ka.generateSecret();

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(secret);
        sha.update(cfg.key);
        byte[] kBytes = Arrays.copyOf(sha.digest(), cfg.key.length);  // tamanho da SKey (128/192/256 bits)
        k = new SecretKeySpec(kBytes, cfg.algorithm);
    }

    public byte[] encrypt(long seq, byte[] data) throws Exception {
        return run(Cipher.ENCRYPT_MODE, seq, data);
    }

    // Lança AEADBadTagException se a mensagem ou o seq tiverem sido alterados
    public byte[] decrypt(long seq, byte[] data) throws Exception {
        return run(Cipher.DECRYPT_MODE, seq, data);
    }

    private byte[] run(int mode, long seq, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance(cfg.transformation());          // ex: AES/GCM/NoPadding
        c.init(mode, k, new GCMParameterSpec(128, nonce(seq)));      // tag de 128 bits
        c.updateAAD(ByteBuffer.allocate(8).putLong(seq).array());    // seq autenticado (AAD)
        return c.doFinal(data);
    }

    // nonce = IV do .config XOR seq (nos últimos 8 bytes): nunca se repete
    private byte[] nonce(long seq) {
        byte[] n = cfg.iv.clone();
        byte[] s = ByteBuffer.allocate(8).putLong(seq).array();
        for (int i = 0; i < 8; i++) n[n.length - 8 + i] ^= s[i];
        return n;
    }
}
