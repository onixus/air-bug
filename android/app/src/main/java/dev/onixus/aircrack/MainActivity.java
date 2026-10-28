package dev.onixus.aircrack;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.*;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Native Android shell: all analysis is offline, on a single background worker. */
public final class MainActivity extends Activity {
    private static final ExecutorService worker = Executors.newSingleThreadExecutor();
    private static boolean cleanedCache;
    private volatile boolean cancelled;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final ArrayList<View> controls = new ArrayList<>();
    private ApexTokens t;
    private LinearLayout body, results;
    private EditText ssid, bssid;
    private TextView progress;
    private Button run, cancel;
    private volatile boolean busy, destroyed;
    private File capture, dictionary;
    private String captureName = "Файл не выбран", dictionaryName = "Необязательно · только анализ";
    private String ssidValue = "", bssidValue = "", theme = "system", report = "";

    @Override public void onCreate(Bundle state) {
        theme = getPreferences(MODE_PRIVATE).getString("apex.theme", "system");
        boolean dark=theme.equals("dark")||(theme.equals("system")&&(getResources().getConfiguration().uiMode&Configuration.UI_MODE_NIGHT_MASK)==Configuration.UI_MODE_NIGHT_YES);
        setTheme(dark?android.R.style.Theme_Material_NoActionBar:android.R.style.Theme_Material_Light_NoActionBar);
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        // Clean leftovers once per PROCESS, not while an old Activity worker exits.
        if(!cleanedCache) {
            File[] old=getCacheDir().listFiles((dir,name)->name.startsWith("air-audit-"));
            if(old!=null)for(File file:old)file.delete();
            cleanedCache=true;
        }
        try {
            capture=File.createTempFile("air-audit-capture-",".pcap",getCacheDir());
            dictionary=File.createTempFile("air-audit-words-",".txt",getCacheDir());
            capture.delete(); dictionary.delete();
        } catch(IOException e) { throw new IllegalStateException("Private cache unavailable",e); }
        render();
    }
    private int dp(int n) { return Math.round(n*getResources().getDisplayMetrics().density); }
    private TextView text(String value, int size, int color, boolean mono) {
        TextView v = new TextView(this); v.setText(value); v.setTextSize(size); v.setTextColor(color);
        v.setTypeface(mono ? t.mono : t.inter); v.setLineSpacing(dp(4),1); v.setSaveEnabled(false);
        return v;
    }
    private GradientDrawable shape(int fill, int stroke, int width) {
        GradientDrawable d = new GradientDrawable(); d.setColor(fill); d.setCornerRadius(dp(ApexTokens.RADIUS));
        if(width>0) d.setStroke(dp(width),stroke); return d;
    }
    private StateListDrawable interactive(int fill) {
        StateListDrawable d = new StateListDrawable();
        d.addState(new int[]{android.R.attr.state_focused}, shape(fill,t.focus,2));
        d.addState(new int[]{android.R.attr.state_pressed}, shape(fill,t.focus,2));
        d.addState(new int[]{},shape(fill,t.control,1)); return d;
    }
    private LinearLayout column() { LinearLayout l = new LinearLayout(this); l.setOrientation(LinearLayout.VERTICAL); return l; }
    private LinearLayout row() { LinearLayout l = new LinearLayout(this); l.setGravity(Gravity.CENTER_VERTICAL); return l; }
    private void space(LinearLayout parent, int height) { View v = new View(this); parent.addView(v,new LinearLayout.LayoutParams(1,dp(height))); }
    private void add(LinearLayout parent, View v) { parent.addView(v,new LinearLayout.LayoutParams(-1,-2)); }
    private void label(LinearLayout parent, String value) { space(parent,12); add(parent,text(value,ApexTokens.CAPTION,t.secondary,false)); space(parent,8); }
    private LinearLayout card(String overline, String title) {
        LinearLayout c = column(); c.setPadding(dp(16),dp(16),dp(16),dp(16)); c.setBackground(shape(t.surface,t.border,1));
        add(c,text(overline,ApexTokens.OVERLINE,t.muted,true)); space(c,8); add(c,text(title,ApexTokens.H2,t.text,false));
        add(body,c); space(body,16); return c;
    }
    private Button button(String value, boolean primary, Runnable action) {
        Button b = new Button(this); b.setText(value); b.setAllCaps(false); b.setTextSize(ApexTokens.BODY); b.setTypeface(t.inter);
        b.setTextColor(primary?t.onAccent:t.accent); b.setBackground(interactive(primary?t.accent:t.field));
        b.setMinHeight(dp(48)); b.setPadding(dp(12),dp(8),dp(12),dp(8)); b.setStateListAnimator(null);
        b.setOnClickListener(v->action.run()); b.setSaveEnabled(false); return b;
    }
    private EditText field(String hint, String value) {
        EditText e = new EditText(this); e.setTextSize(ApexTokens.BODY); e.setTextColor(t.text); e.setHintTextColor(t.muted);
        e.setTypeface(t.mono); e.setSingleLine(true); e.setHint(hint); e.setText(value);
        e.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        e.setBackground(interactive(t.field)); e.setPadding(dp(12),dp(12),dp(12),dp(12)); e.setMinHeight(dp(48));
        e.setSaveEnabled(false); e.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        controls.add(e); return e;
    }
    private void remember() {
        if(ssid!=null) ssidValue=ssid.getText().toString();
        if(bssid!=null) bssidValue=bssid.getText().toString();
    }
    @SuppressWarnings("deprecation")
    private void render() {
        t = new ApexTokens(this,theme); controls.clear();
        getWindow().setStatusBarColor(t.canvas); getWindow().setNavigationBarColor(t.canvas);
        getWindow().getDecorView().setSystemUiVisibility(t.dark?0:View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR|View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        LinearLayout root=column(); root.setBackgroundColor(t.canvas);
        // Target 36 is edge-to-edge. Insets are applied before the 56dp application header.
        root.setOnApplyWindowInsetsListener((v,insets)->{
            if(android.os.Build.VERSION.SDK_INT>=30) {
                android.graphics.Insets bars=insets.getInsets(android.view.WindowInsets.Type.systemBars()|android.view.WindowInsets.Type.displayCutout()|android.view.WindowInsets.Type.ime());
                v.setPadding(bars.left,bars.top,bars.right,bars.bottom);
            } else {
                v.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        LinearLayout header=row(); header.setPadding(dp(20),0,dp(12),0); header.setBackgroundColor(t.surface);
        header.addView(new LucideIcon(this,"shield",t.accent),new LinearLayout.LayoutParams(dp(24),dp(24)));
        TextView brand=text("  AIRCRACK",ApexTokens.H2,t.text,false);
        header.addView(brand,new LinearLayout.LayoutParams(0,-2,1));
        Button themeButton=button("Тема",false,this::chooseTheme); themeButton.setContentDescription("Тема: "+theme+". Тёмная, светлая или системная");
        header.addView(themeButton,new LinearLayout.LayoutParams(dp(88),dp(48))); controls.add(themeButton);
        root.addView(header,new LinearLayout.LayoutParams(-1,dp(ApexTokens.HEADER)));
        ScrollView scroll=new ScrollView(this); scroll.setFillViewport(true);
        body=column(); body.setPadding(dp(20),dp(24),dp(20),dp(24)); scroll.addView(body);
        root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        add(body,text("APEX / MOBILE LAB",ApexTokens.OVERLINE,t.accent,true)); space(body,8);
        add(body,text("Аудит без эфира",ApexTokens.H1,t.text,false)); space(body,8);
        add(body,text("Локальный анализ Wi-Fi захватов. Ваши файлы и пароли остаются на устройстве.",ApexTokens.BODY,t.secondary,false)); space(body,20);
        LinearLayout badge=row(); badge.setPadding(dp(12),dp(12),dp(12),dp(12)); badge.setBackground(shape(t.successSubtle,t.success,1));
        badge.addView(new LucideIcon(this,"shield",t.success),new LinearLayout.LayoutParams(dp(20),dp(20)));
        badge.addView(text("  Офлайн · без root · без сети",ApexTokens.BODY_SM,t.success,false)); add(body,badge); space(body,20);

        LinearLayout files=card("01 / ИСТОЧНИКИ","Выберите локальные файлы");
        label(files,"Захват · PCAP / PCAPNG · до 4 MiB");
        Button pick=button("Открыть захват",false,()->pickFile(10)); add(files,pick); controls.add(pick);
        space(files,8); add(files,text(captureName,ApexTokens.CAPTION,t.secondary,true));
        label(files,"Словарь · UTF-8 TXT · до 16 MiB");
        Button words=button("Открыть словарь",false,()->pickFile(11)); add(files,words); controls.add(words);
        space(files,8); add(files,text(dictionaryName,ApexTokens.CAPTION,t.secondary,true));
        space(files,12); Button demo=button("Загрузить учебный пример",false,this::loadDemo); add(files,demo); controls.add(demo);
        if(dictionary.isFile()) {
            space(files,8); Button clear=button("Убрать словарь · только анализ",false,()->{remember(); dictionary.delete(); dictionaryName="Необязательно · только анализ"; report=""; render();}); add(files,clear); controls.add(clear);
        }
        LinearLayout selection=card("02 / ВЫБОР СЕТИ","Параметры проверки");
        label(selection,"SSID · если отсутствует в захвате или неоднозначен"); ssid=field("Автоматически из beacon",ssidValue); add(selection,ssid);
        label(selection,"BSSID · обязателен при нескольких сетях"); bssid=field("aa:bb:cc:dd:ee:ff",bssidValue); add(selection,bssid);
        space(selection,12); add(selection,text("Сначала выполните анализ без словаря. Нажмите сеть в отчёте, чтобы выбрать её BSSID. Поддерживаются WPA2 M1/M2, M2/M3 (descriptor v2) и PMKID.",ApexTokens.BODY_SM,t.secondary,false));

        LinearLayout action=card("03 / ЗАПУСК","Запуск анализа");
        space(action,12); run=button(dictionary.isFile()?"Проверить словарь":"Анализировать захват",true,this::startAnalysis); add(action,run);
        space(action,12); progress=text("Готов к работе",ApexTokens.CAPTION,t.secondary,true); progress.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE); add(action,progress);
        cancel=button("Остановить",false,()->{cancelled=true; NativeBridge.control(1);}); space(action,8); add(action,cancel); cancel.setVisibility(View.GONE);
        results=column(); add(body,results); showReport();
        add(body,text("RUST CORE / APEX DESIGN SYSTEM",ApexTokens.OVERLINE,t.muted,true)); space(body,8);
        add(body,text("Нет live/monitor-захвата, инъекций и WPA3. Лимиты: 32 768 пакетов и 128 EAPOL keys. Не импортируйте недоверенные захваты. Аудит — только по письменному разрешению владельца сети или правилам вовлечения.",ApexTokens.CAPTION,t.secondary,false));
        setContentView(root); root.requestApplyInsets(); setBusy(busy);
    }
    private void chooseTheme() {
        remember();
        String[] modes={"dark","light","system"}, names={"Тёмная","Светлая","Как в системе"};
        android.app.Dialog dialog=new android.app.Dialog(this);
        dialog.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE);
        LinearLayout content=column(); content.setPadding(dp(20),dp(20),dp(20),dp(20));
        add(content,text("Тема Apex",ApexTokens.H2,t.text,false));
        for(int i=0;i<modes.length;i++) {
            final String mode=modes[i]; space(content,12);
            add(content,button(names[i]+(theme.equals(mode)?" · выбрана":""),false,()->{
                theme=mode; getPreferences(MODE_PRIVATE).edit().putString("apex.theme",theme).apply(); dialog.dismiss(); render();
            }));
        }
        dialog.setContentView(content);
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.getWindow().setBackgroundDrawable(shape(t.surface,t.border,1)); dialog.show();
        dialog.getWindow().setLayout(getResources().getDisplayMetrics().widthPixels-dp(40),-2);
    }
    private void pickFile(int request) {
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT); i.addCategory(Intent.CATEGORY_OPENABLE); i.setType("*/*");
        startActivityForResult(i,request);
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null||busy) return;
        remember(); Uri uri=data.getData(); boolean isCapture=request==10;
        File target=isCapture?capture:dictionary; long limit=(isCapture?4L:16L)*1024*1024;
        // Provider I/O is untrusted and must not block the UI thread.
        setBusy(true);
        worker.execute(()->{
            String error=null;
            try(InputStream input=getContentResolver().openInputStream(uri)) {
                if(input==null) throw new IOException("Не удалось открыть файл");
                copyLimited(input,target,limit);
            } catch(Exception e) { target.delete(); error="Ошибка импорта: "+e.getMessage(); }
            String message=error;
            handler.post(()->{if(destroyed)return; busy=false;
                if(message!=null) { if(isCapture) captureName="Файл не выбран"; else dictionaryName="Не выбран"; report=errorReport(message); }
                else { if(isCapture) captureName="Захват · "+target.length()+" bytes"; else dictionaryName="Словарь · "+target.length()+" bytes"; report=""; }
                render();
            });
        });
    }
    private void copyLimited(InputStream input,File target,long limit) throws IOException {
        try(FileOutputStream output=new FileOutputStream(target,false)) {
            byte[] buffer=new byte[8192]; long count=0; int n;
            while((n=input.read(buffer))!=-1) {
                if(destroyed||cancelled||Thread.currentThread().isInterrupted()) throw new IOException("Импорт отменён");
                count+=n; if(count>limit) throw new IOException("Превышен лимит размера файла"); output.write(buffer,0,n);
            }
        }
    }
    private void loadDemo() {
        remember(); setBusy(true);
        worker.execute(()->{
            String error=null;
            try(InputStream p=getAssets().open("demo/wpa2-radiotap.pcap"); InputStream w=getAssets().open("demo/words.txt")) {
                copyLimited(p,capture,4L*1024*1024); copyLimited(w,dictionary,16L*1024*1024);
            } catch(Exception e) { capture.delete(); dictionary.delete(); error=e.getMessage(); }
            String message=error;
            handler.post(()->{if(destroyed)return; busy=false; ssidValue=""; bssidValue="";
                captureName=message==null?"Учебный · wpa2-radiotap.pcap":"Файл не выбран";
                dictionaryName=message==null?"Учебный · words.txt":"Не выбран";
                report=message==null?"":errorReport(message); render();
            });
        });
    }
    private String errorReport(String message) {
        try { return new JSONObject().put("status","error").put("message",message).toString(); }
        catch(Exception ignored) { return ""; }
    }
    private void startAnalysis() {
        remember();
        if(!capture.isFile()) { report=errorReport("Сначала выберите захват"); showReport(); return; }
        final String request;
        try { request=new JSONObject().put("capture",capture.getAbsolutePath()).put("wordlist",dictionary.isFile()?dictionary.getAbsolutePath():"").put("ssid",ssidValue).put("bssid",bssidValue.trim()).toString(); }
        catch(Exception e) { report=errorReport(e.getMessage()); showReport(); return; }
        report=""; showReport(); setBusy(true); cancel.setVisibility(View.VISIBLE); handler.post(tick);
        worker.execute(()->{
            String value;
            try {
                NativeBridge.control(0);
                if(destroyed||cancelled) NativeBridge.control(1);
                value=NativeBridge.run(request); if(value==null)value=errorReport("JNI не вернул результат");
            }
            catch(Exception e) { value=errorReport("Ошибка анализа"); }
            if(destroyed) { capture.delete(); dictionary.delete(); return; }
            final String result=value;
            handler.post(()->{if(destroyed)return; handler.removeCallbacks(tick); setBusy(false); report=result; showReport(); progress.setText("Завершено · проверено строк: "+NativeBridge.control(2)); });
        });
    }
    private final Runnable tick=new Runnable(){@Override public void run(){if(!busy||destroyed)return; progress.setText("В работе · проверено строк: "+NativeBridge.control(2)); handler.postDelayed(this,500);}};
    private void setBusy(boolean value) {
        busy=value; if(value)cancelled=false; for(View v:controls)v.setEnabled(!value); if(run!=null)run.setEnabled(!value);
        if(cancel!=null&&!value)cancel.setVisibility(View.GONE);
        if(progress!=null&&value)progress.setText("Обработка в фоне…");
    }
    private void showReport() {
        if(results==null)return; results.removeAllViews(); if(report.isEmpty())return;
        try {
            JSONObject data=new JSONObject(report); String status=data.optString("status");
            boolean bad=status.equals("error"), good=status.equals("found")||status.equals("inspected");
            int ink=bad?t.danger:good?t.success:t.warning; int fill=bad?t.dangerSubtle:good?t.successSubtle:t.warningSubtle;
            String title=switch(status){case "found"->"Совпадение найдено";case "inspected"->"Анализ завершён";case "not_found"->"Пароль не найден";case "cancelled"->"Проверка остановлена";default->"Ошибка";};
            LinearLayout box=column(); box.setPadding(dp(16),dp(16),dp(16),dp(16)); box.setBackground(shape(fill,ink,1));
            LinearLayout headline=row(); headline.addView(new LucideIcon(this,good?"check":"alert",ink),new LinearLayout.LayoutParams(dp(20),dp(20)));
            headline.addView(text("  "+title,ApexTokens.H2,ink,false)); add(box,headline); space(box,12);
            if(bad) add(box,text(data.optString("message"),ApexTokens.BODY,t.text,false));
            else {
                add(box,text("Пакеты: "+data.optInt("packets")+" · разобрано: "+data.optInt("parsed")+" · пропущено: "+data.optInt("skipped")+"\nПроверочные записи: "+data.optInt("sessions"),ApexTokens.BODY_SM,t.secondary,false));
                JSONArray networks=data.optJSONArray("networks");
                if(networks!=null)for(int i=0;i<networks.length();i++) {
                    JSONObject network=networks.getJSONObject(i); String address=network.getString("bssid");
                    String names=network.getJSONArray("ssids").join(", ");
                    space(box,12); Button networkButton=button(address+"\n"+(names.isEmpty()?"SSID отсутствует":names)+" · "+network.optInt("sessions")+" записей",false,()->{remember(); bssidValue=address; render();});
                    networkButton.setTextSize(ApexTokens.CAPTION); networkButton.setTypeface(t.mono); add(box,networkButton);
                }
                if(status.equals("inspected")&&data.optInt("sessions")==0) { space(box,12); add(box,text("Поддерживаемых handshake или PMKID нет. Проверка словаря недоступна.",ApexTokens.BODY,t.warning,false)); }
                if(status.equals("found")) {
                    space(box,12); add(box,text("Секрет · не публикуйте результат",ApexTokens.CAPTION,t.warning,false));
                    TextView secret=text("••••••••••••",ApexTokens.BODY,t.text,true); space(box,8); add(box,secret);
                    space(box,8); Button reveal=button("Показать / скрыть пароль",false,()->secret.setText(secret.getText().toString().startsWith("•")?data.optString("passphrase"):"••••••••••••")); add(box,reveal);
                }
            }
            add(results,box); space(results,20);
        } catch(Exception e) { add(results,text("Некорректный ответ ядра",ApexTokens.BODY,t.danger,false)); }
    }
    @Override public void onConfigurationChanged(Configuration config) { super.onConfigurationChanged(config); if(!busy){remember();render();} }
    @Override protected void onStop() { super.onStop(); if(busy){cancelled=true; NativeBridge.control(1);} }
    @Override protected void onDestroy() {
        destroyed=true; cancelled=true; NativeBridge.control(1); handler.removeCallbacksAndMessages(null);
        // The process-wide serial worker prevents overlapping native jobs. Cleanup
        // runs after pending I/O and uses unique files belonging only to this Activity.
        worker.execute(()->{capture.delete(); dictionary.delete();});
        report=""; super.onDestroy();
    }
}
