package common;

import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.HexFormat;

// Lê o proxycrypto.config / sservercrypto.config
public class CryptoConfig {

    public String algorithm;   // AES, ChaCha20
    public String mode;        // GCM, CTR, CBC, Poly1305, NULL
    public String padding;     // NoPadding, PKCS5Padding
    public String ivSize;      // tamanho do IV em bits (ex: 96) ou NULL
    public byte[] iv;          // valor do IV ou null
    public String mac;         // HmacSHA256, HmacSHA384, HmacSHA512 ou null
    public byte[] key;
    public byte[] macKey;      // null se não houver

    public static CryptoConfig load(String path) throws Exception {
        Element root = DocumentBuilderFactory.newInstance().newDocumentBuilder()
                .parse(new File(path)).getDocumentElement();
        Element sym = (Element) root.getElementsByTagName("SymCipherSuite").item(0);
        Element macSuite = (Element) root.getElementsByTagName("MACSuite").item(0);

        CryptoConfig c = new CryptoConfig();
        c.algorithm = get(sym, "Algorithm");
        c.mode = get(sym, "Mode");
        c.padding = get(sym, "Padding");
        c.ivSize = get(sym, "IVSize");
        String iv = get(sym, "IV");
        c.iv = iv.equals("NULL") ? null : HexFormat.of().parseHex(iv);
        String m = get(macSuite, "Algorithm");
        c.mac = m.equals("NULL") ? null : m.replace("HMAC-", "Hmac");   // HMAC-SHA256 -> HmacSHA256
        c.key = HexFormat.of().parseHex(get(root, "SKey"));
        String mk = get(root, "MacKey");
        c.macKey = mk.equals("NULL") ? null : HexFormat.of().parseHex(mk);
        return c;
    }

    private static String get(Element parent, String tag) {
        return parent.getElementsByTagName(tag).item(0).getTextContent().trim();
    }

    // Nome para Cipher.getInstance(...)
    public String transformation() {
        if (mode.equals("Poly1305")) return "ChaCha20-Poly1305";
        if (mode.equals("NULL")) return algorithm;               // ex: ChaCha20
        return algorithm + "/" + mode + "/" + padding;          // ex: AES/GCM/NoPadding
    }

    // GCM e ChaCha20-Poly1305 já autenticam: não precisam de HMAC
    public boolean isAead() {
        return mode.equals("GCM") || mode.equals("Poly1305");
    }

    // Proposta enviada na mensagem 1, no formato do enunciado ALG/MODE/IV/Padding
    // (+ o MAC no fim), ex: "AES/GCM/96/NoPadding/NULL"
    public String suite() {
        return algorithm + "/" + mode + "/" + ivSize + "/" + padding + "/" + (mac == null ? "NULL" : mac);
    }
}
