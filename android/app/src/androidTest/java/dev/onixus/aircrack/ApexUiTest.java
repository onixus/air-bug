package dev.onixus.aircrack;

import android.test.ActivityInstrumentationTestCase2;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;
import java.io.File;
import java.io.FileOutputStream;

@SuppressWarnings("deprecation")
public final class ApexUiTest extends ActivityInstrumentationTestCase2<MainActivity> {
    public ApexUiTest(){super(MainActivity.class);}
    private View find(View view,String text) {
        if(view instanceof TextView && ((TextView)view).getText().toString().equals(text))return view;
        if(view instanceof ViewGroup) { ViewGroup group=(ViewGroup)view; for(int i=0;i<group.getChildCount();i++){View result=find(group.getChildAt(i),text);if(result!=null)return result;} }
        return null;
    }
    private View waitFor(MainActivity activity,String text) throws Exception {
        long end=System.currentTimeMillis()+15000;
        while(System.currentTimeMillis()<end){
            final View[] result={null}; getInstrumentation().runOnMainSync(()->result[0]=find(activity.getWindow().getDecorView(),text));
            if(result[0]!=null)return result[0]; Thread.sleep(50);
        }
        fail("Missing UI state: "+text); return null;
    }
    private void click(MainActivity activity,String text) throws Exception {
        View view=waitFor(activity,text); getInstrumentation().runOnMainSync(()->view.performClick()); getInstrumentation().waitForIdleSync();
    }
    private void screenshot(MainActivity activity,String name) throws Exception {
        // Tests ONLY: production retains FLAG_SECURE. Fixture contains no real secrets.
        getInstrumentation().runOnMainSync(()->activity.getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE));
        getInstrumentation().waitForIdleSync(); Thread.sleep(300);
        android.graphics.Bitmap bitmap=getInstrumentation().getUiAutomation().takeScreenshot(); assertNotNull(bitmap);
        File file=new File(activity.getExternalFilesDir(null),name+".png");
        try(FileOutputStream stream=new FileOutputStream(file)){assertTrue(bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,stream));}
        bitmap.recycle();
        // Export synthetic screenshots before Gradle uninstalls the test package.
        try(android.os.ParcelFileDescriptor.AutoCloseInputStream stream=new android.os.ParcelFileDescriptor.AutoCloseInputStream(
            getInstrumentation().getUiAutomation().executeShellCommand("cp "+file.getAbsolutePath()+" /data/local/tmp/"+name+".png"))) {
            byte[] buffer=new byte[1024]; while(stream.read(buffer)!=-1) { /* drain command */ }
        }
        getInstrumentation().runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE));
    }
    private void flow(String theme) throws Exception {
        getInstrumentation().getTargetContext().getSharedPreferences("MainActivity",0).edit().putString("apex.theme",theme).commit();
        MainActivity activity=getActivity(); getInstrumentation().waitForIdleSync();
        getInstrumentation().runOnMainSync(()->activity.getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON));
        screenshot(activity,"apex-"+theme);
        click(activity,"Загрузить учебный пример"); waitFor(activity,"Учебный · words.txt");
        click(activity,"Проверить словарь");
        waitFor(activity,"  Совпадение найдено");
        // Ensure the secret is hidden by default, even in a successful report.
        assertNull(find(activity.getWindow().getDecorView(),"correct horse battery"));
        getInstrumentation().runOnMainSync(()->{
            // Prepare the synthetic screenshot window before waiting for its layout.
            activity.getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
            activity.getWindow().getDecorView().requestLayout();
        });
        // Reacquire after each frame: Activity configuration/measurement may
        // replace the report view while the analysis result is already present.
        final String[] dimensions={"not laid out"};
        long layoutDeadline=System.currentTimeMillis()+15000;
        boolean fullyVisible=false;
        while(System.currentTimeMillis()<layoutDeadline) {
            final boolean[] visible={false};
            getInstrumentation().runOnMainSync(()->{
                View status=find(activity.getWindow().getDecorView(),"  Совпадение найдено");
                if(status==null)return;
                View card=(View)status.getParent().getParent();
                dimensions[0]="card="+card.getWidth()+"x"+card.getHeight()+", attached="+card.isAttachedToWindow();
                if(card.getWidth()==0||card.getHeight()==0){activity.getWindow().getDecorView().requestLayout();return;}
                android.view.ViewParent ancestor=card.getParent();
                while(ancestor!=null&&!(ancestor instanceof ScrollView))ancestor=ancestor.getParent();
                if(!(ancestor instanceof ScrollView))return;
                ScrollView scroller=(ScrollView)ancestor;
                scroller.scrollTo(0,Math.max(0,scroller.getChildAt(0).getHeight()-scroller.getHeight()));
                android.graphics.Rect rect=new android.graphics.Rect();
                boolean shown=card.getGlobalVisibleRect(rect);
                dimensions[0]+=", visible="+rect;
                visible[0]=shown&&rect.height()>=card.getHeight()-1;
            });
            if(visible[0]){fullyVisible=true;break;}
            Thread.sleep(50);
        }
        assertTrue("Result card must fit entirely in the screenshot: "+dimensions[0],fullyVisible);
        waitFor(activity,"••••••••••••");
        screenshot(activity,"apex-"+theme+"-result");
    }
    public void testDarkThemePipeline() throws Exception { flow("dark"); }
    public void testLightThemePipeline() throws Exception { flow("light"); }
}
