package me.daei.soundmeter;

import android.os.Bundle;
import android.support.v7.p014a.C0231u;
import android.util.Log;
import android.widget.Toast;
import java.io.File;
import me.daei.soundmeter.widget.SoundDiscView;

public class SecondActivity extends C0231u {
    float f1618l;
    private boolean f1619m;
    private boolean f1620n;
    private Thread f1621o;
    private SoundDiscView f1622p;
    private C0312e f1623q;

    public SecondActivity() {
        this.f1619m = true;
        this.f1620n = true;
        this.f1618l = 10000.0f;
    }

    private void m2869j() {
        this.f1621o = new Thread(new C0314g(this));
        this.f1621o.start();
    }

    public void m2870a(File file) {
        try {
            this.f1623q.m2875a(file);
            if (this.f1623q.m2876b()) {
                m2869j();
            } else {
                Toast.makeText(this, "start Listen Audio", 0).show();
            }
        } catch (Exception e) {
            Toast.makeText(this, "no permission", 0).show();
            e.printStackTrace();
        }
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(2130968602);
        this.f1623q = new C0312e();
    }

    protected void onDestroy() {
        if (this.f1621o != null) {
            this.f1620n = false;
            this.f1621o = null;
        }
        this.f1623q.m2878d();
        super.onDestroy();
    }

    protected void onPause() {
        super.onPause();
        this.f1619m = false;
        this.f1623q.m2878d();
        this.f1621o = null;
    }

    protected void onResume() {
        super.onResume();
        this.f1622p = (SoundDiscView) findViewById(2131492948);
        this.f1619m = true;
        File a = C0310c.m2873a("temp.amr");
        if (a != null) {
            Log.v("file", "file =" + a.getAbsolutePath());
            m2870a(a);
            return;
        }
        Toast.makeText(getApplicationContext(), "fail to make file", 1).show();
    }
}
