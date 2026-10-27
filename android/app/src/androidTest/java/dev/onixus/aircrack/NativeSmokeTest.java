package dev.onixus.aircrack;

import android.test.InstrumentationTestCase;
import org.json.JSONObject;
import java.io.*;

/** Runs the real packaged JNI/ARM library, not a mocked Kotlin/Java implementation. */
@SuppressWarnings("deprecation")
public final class NativeSmokeTest extends InstrumentationTestCase {
    private File fixture(String asset) throws Exception {
        File out=File.createTempFile("jni-smoke-",".data",getInstrumentation().getTargetContext().getCacheDir());
        try(InputStream in=getInstrumentation().getTargetContext().getAssets().open("demo/"+asset); FileOutputStream stream=new FileOutputStream(out)) { byte[] buffer=new byte[8192]; int n; while((n=in.read(buffer))!=-1)stream.write(buffer,0,n); }
        return out;
    }
    public void testPackagedPipeline() throws Exception {
        File capture=fixture("wpa2-radiotap.pcap"), words=fixture("words.txt");
        try {
            NativeBridge.control(0);
            JSONObject inspect=new JSONObject(NativeBridge.run(new JSONObject().put("capture",capture.getPath()).toString()));
            assertEquals("inspected",inspect.getString("status")); assertEquals(1,inspect.getInt("sessions"));
            JSONObject request=new JSONObject().put("capture",capture.getPath()).put("wordlist",words.getPath());
            JSONObject found=new JSONObject(NativeBridge.run(request.toString()));
            assertEquals("found",found.getString("status")); assertEquals("correct horse battery",found.getString("passphrase"));
            assertTrue(NativeBridge.control(2)>0);
            request.put("ssid","wrong");
            assertEquals("error",new JSONObject(NativeBridge.run(request.toString())).getString("status"));
            assertEquals("error",new JSONObject(NativeBridge.run("bad json")).getString("status"));
            NativeBridge.control(1);
            assertEquals("cancelled",new JSONObject(NativeBridge.run(new JSONObject().put("capture",capture.getPath()).toString())).getString("status"));
        } finally { capture.delete(); words.delete(); NativeBridge.control(0); }
    }
    public void testNotFoundAndInvalidDictionary() throws Exception {
        File capture=fixture("wpa2-radiotap.pcap"), words=fixture("words.txt");
        try {
            NativeBridge.control(0);
            try(FileOutputStream out=new FileOutputStream(words)){out.write("wrong-password\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
            JSONObject request=new JSONObject().put("capture",capture.getPath()).put("wordlist",words.getPath());
            assertEquals("not_found",new JSONObject(NativeBridge.run(request.toString())).getString("status"));
            try(FileOutputStream out=new FileOutputStream(words)){out.write(new byte[]{(byte)255});}
            assertEquals("error",new JSONObject(NativeBridge.run(request.toString())).getString("status"));
        } finally { capture.delete(); words.delete(); }
    }
    public void testPackagedM2M3AndPmkid() throws Exception {
        File words=fixture("words.txt");
        try {
            for(String name:new String[]{"wpa2-m2m3.pcap","wpa2-pmkid.pcap","wpa2-pmkid-assoc.pcap","wpa2-pmkid-reassoc.pcap"}) {
                File capture=File.createTempFile("jni-new-target-",".pcap",getInstrumentation().getTargetContext().getCacheDir());
                try {
                    try(InputStream in=getInstrumentation().getContext().getAssets().open("interop/"+name);FileOutputStream out=new FileOutputStream(capture)) {
                        byte[] buffer=new byte[8192];int n;while((n=in.read(buffer))!=-1)out.write(buffer,0,n);
                    }
                    NativeBridge.control(0);
                    JSONObject request=new JSONObject().put("capture",capture.getPath());
                    JSONObject report=new JSONObject(NativeBridge.run(request.toString()));
                    assertEquals(name,"inspected",report.getString("status"));
                    assertEquals(name,1,report.getInt("sessions"));
                    assertEquals(name,name.contains("pmkid")?1:0,report.getInt("pmkids"));
                    request.put("wordlist",words.getPath());
                    JSONObject found=new JSONObject(NativeBridge.run(request.toString()));
                    assertEquals(name,"found",found.getString("status"));
                    assertEquals(name,"correct horse battery",found.getString("passphrase"));
                    request.put("ssid","Wrong Network");
                    assertEquals(name,"error",new JSONObject(NativeBridge.run(request.toString())).getString("status"));
                } finally { capture.delete(); }
            }
        } finally { words.delete();NativeBridge.control(0); }
    }

}
