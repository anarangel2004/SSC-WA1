package common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

// Formato das mensagens: version(2) | release(2) | type(1) | size(4) || payload
public class Wire {

    public static final int HELLO = 1, SERVER_HELLO = 2, REQUEST = 3, DATA = 4, END = 5, ALERT = 255;

    public static class Message {
        public int type;
        public byte[] payload;
    }

    public static void write(DataOutputStream out, int type, byte[] payload) throws IOException {
        out.writeShort(1);            // version
        out.writeShort(1);            // release
        out.writeByte(type);
        out.writeInt(payload.length);
        out.write(payload);
        out.flush();
    }

    public static Message read(DataInputStream in) throws IOException {
        if (in.readShort() != 1 || in.readShort() != 1) throw new IOException("Wrong Version");
        Message m = new Message();
        m.type = in.readUnsignedByte();
        int size = in.readInt();
        if (size < 0 || size > 1_000_000) throw new IOException("Invalid size: " + size);
        m.payload = new byte[size];
        in.readFully(m.payload);
        return m;
    }
}
