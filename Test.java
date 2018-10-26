

public class Test {
    public static void main(String[] args){
        String fileName = "D:/IP_basic_2018W42_single_WGS84.dat";
        IPLocate iplocate = IPLocate.loadDat(fileName);
        String result = iplocate.locate_ip("1.0.1.0");
        System.out.println(result);
    }
}
