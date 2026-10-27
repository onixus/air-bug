package dev.onixus.aircrack;

/** Desktop JVM exercises the same JNI exports; not a substitute for ART/UI tests. */
public final class HostJniSmoke {
    private static void expect(String value,String fragment) {
        if(value==null||!value.contains(fragment))throw new AssertionError("Missing expected JNI result: "+fragment);
    }
    public static void main(String[] args) throws Exception {
        String root=args[0].replace("\\","\\\\").replace("\"","\\\"");
        String capture="{\"capture\":\""+root+"/tests/fixtures/wpa2-radiotap.pcap\"";
        NativeBridge.control(0);
        expect(NativeBridge.run(capture+"}"),"\"status\":\"inspected\"");
        String request=capture+",\"wordlist\":\""+root+"/tests/fixtures/words.txt\"}";
        String found=NativeBridge.run(request);
        expect(found,"\"status\":\"found\""); expect(found,"correct horse battery");
        if(NativeBridge.control(2)==0)throw new AssertionError("Missing progress");
        expect(NativeBridge.run(capture+",\"wordlist\":\""+root+"/tests/fixtures/wrong-words.txt\"}"),"\"status\":\"not_found\"");
        for(String file:new String[]{"wpa2-m3m4.pcap","wpa1-m3m4.pcap","wpa2-m234-zero.pcap","wpa2-v3-m234-zero.pcap","wds-m3m4.pcap","ft-psk.pcap","ft-psk-fragmented.pcap","wpa2-fragmented-m2.pcap","wpa2-v3.pcap","wpa2-v3-m2m3.pcap","wpa1-m1m2.pcap","wpa1-m2m3.pcap","wpa2-m2m3.pcap","wpa2-pmkid.pcap","wpa2-pmkid-assoc.pcap","wpa2-pmkid-reassoc.pcap"}) {
            String input="{\"capture\":\""+root+"/tests/fixtures/"+file+"\",\"wordlist\":\""+root+"/tests/fixtures/words.txt\"}";
            expect(NativeBridge.run(input),"\"status\":\"found\"");
        }
        expect(NativeBridge.run("not JSON"),"\"status\":\"error\"");
        NativeBridge.control(1); expect(NativeBridge.run(capture+"}"),"\"status\":\"cancelled\"");
        NativeBridge.control(0);
        System.out.println("JNI smoke: inspect, known answer, not found, errors, cancellation, progress PASS (no secrets logged)");
    }
}
