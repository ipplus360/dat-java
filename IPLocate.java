import java.io.File;
import java.io.FileInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IPLocate {

    private long base_len = 64;
    private long offset_addr = 0;
    private long offset_owner = 0;
    private byte[] offset_infe;
    private Pattern ip_re = Pattern.compile("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");

    public long ipToLong(String ipAddress) {
        long result = 0;
        String[] ipAddressInArray = ipAddress.split("\\.");
        for (int i = 3; i >= 0; i--) {
            long ip = Long.parseLong(ipAddressInArray[3 - i]);
            result |= ip << (i * 8);
        }
        return result;
    }

    public static String bytetoChar(byte[] bytes, Integer src, Integer dst) {
        byte[] asses = new byte[dst];
        System.arraycopy(bytes, src, asses, 0, dst);
        String retuchr = new String(asses);
        return retuchr;
    }

    public static Integer bytetoInt(byte[] bytes, Integer src, Integer dst) {
        byte[] asses = new byte[dst];
        System.arraycopy(bytes, src, asses, 0, dst);
        Integer restu = byteArrayToInt(asses);
        return restu;
    }

    public static long byteArrayToInt2(byte[] b) {
        long num = 0;
        for (int ix = 3; ix >= 0; --ix) {
            num <<= 8;
            num |= (b[ix] & 0xff);
        }
        return num;
    }

    public static long bytetoInt2(byte[] bytes, Integer src, Integer dst) {
        byte[] asses = new byte[4];
        System.arraycopy(bytes, src, asses, 0, 4);
        long restu = byteArrayToInt2(asses);
        return restu;
    }

    public String locate_ip(String ip) {
        Matcher m = this.ip_re.matcher(ip);
        Long nip;
        if (m.find()) {
            nip = ipToLong(m.group(0));
        } else {
            return "Error IP";
        }
        ;
        long record_min = 0;
        long record_max = this.offset_addr / this.base_len - 1;
        long record_mid = (record_min + record_max) / 2;
        long mult_re_ba_l;
        while (record_max - record_min >= 0) {

            mult_re_ba_l = record_mid * this.base_len;
            Integer mult_re_ba = (int) mult_re_ba_l;
            Long minip;
            Long maxip;
            minip = bytetoInt2(this.offset_infe, mult_re_ba, 4);
            maxip = bytetoInt2(this.offset_infe, mult_re_ba + 4, 4);
            if (nip < minip) {
                record_max = record_mid - 1;
            } else if ((nip.equals(minip)) | (nip > minip & nip < maxip) | (nip.equals(maxip))) {
                Integer addr_begin = bytetoInt(this.offset_infe, mult_re_ba + 8, 8);
                Integer addr_length = bytetoInt(this.offset_infe, mult_re_ba + 16, 8);
                Integer owner_begin = bytetoInt(this.offset_infe, mult_re_ba + 24, 8);
                Integer owner_length = bytetoInt(this.offset_infe, mult_re_ba + 32, 8);
                String wgs_lon = bytetoChar(this.offset_infe, mult_re_ba + 40, 12).trim();
                String wgs_lat = bytetoChar(this.offset_infe, mult_re_ba + 52, 12).trim();
                String addr_bundle = bytetoChar(this.offset_infe, addr_begin, addr_length).trim();
                String owner = bytetoChar(this.offset_infe, owner_begin, owner_length).trim();
                String sum_temp = minip.toString() + "|" + maxip.toString() + "|" + addr_bundle + "|" + wgs_lon + "|" + wgs_lat + "|" + owner;
                return sum_temp;
            } else if (nip > maxip) {
                record_min = record_mid + 1;
            } else {
                return "ERROR Case";
            }
            ;
            record_mid = (record_min + record_max) / 2;
        }
        return "Not Found.";

    }

    public static byte[] fileTobyte(String path) {
        try {
            FileInputStream in = new FileInputStream(new File(path));
            byte[] data = new byte[in.available()];
            in.read(data);
            in.close();
            return data;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static int byteArrayToInt(byte[] b) {
        return b[0] & 0xFF << 0 |
                (b[1] & 0xFF) << 8 |
                (b[2] & 0xFF) << 16 |
                (b[3] & 0xFF) << 24;
    }

    public static long bytesToLong(byte[] b) {
        long l = ((((long) b[7]) << 56) | (((long) b[6] & 0xff) << 48) | (((long) b[5] & 0xff) << 40)
                | (((long) b[4] & 0xff) << 32) | (((long) b[3] & 0xff) << 24) | (((long) b[2] & 0xff) << 16)
                | (((long) b[1] & 0xff) << 8) | (((long) b[0] & 0xff)));

        return l;
    }

    public static IPLocate loadDat(String file_name){
        IPLocate h = new IPLocate();
        byte[] bytes = fileTobyte(file_name);
        byte[] asse = new byte[bytes.length - 16];
        byte[] asse1 = new byte[8];
        byte[] asse2 = new byte[8];
        System.arraycopy(bytes, 16, asse, 0, bytes.length - 16);
        System.arraycopy(bytes, 0, asse1, 0, 8);
        System.arraycopy(bytes, 8, asse2, 0, 8);
        System.out.println("load dat over");
        h.offset_addr = bytesToLong(asse1);
        h.offset_owner = bytesToLong(asse2);
        h.offset_infe = asse;

        return h;
    }
}
