package com.ssctf.seclreg;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

public class Seclreg extends Activity {
    private Button f356a;
    private Button f357b;
    private EditText f358c;
    private EditText f359d;
    private Seclo0o f360e;
    private String f361f;
    private String f362g;
    private String f363h;

    static {
        System.loadLibrary("plokm");
    }

    public Seclreg() {
        this.f356a = null;
        this.f357b = null;
        this.f358c = null;
        this.f359d = null;
        this.f360e = new Seclo0o();
        this.f361f = null;
        this.f362g = null;
        this.f363h = null;
    }

    public void m585a() {
        this.f356a = (Button) findViewById(R.id.but_sign);
        this.f357b = (Button) findViewById(R.id.but_exit);
        this.f358c = (EditText) findViewById(R.id.txt_user);
        this.f359d = (EditText) findViewById(R.id.txt_no);
    }

    public void m586a(String str) {
        Toast.makeText(this, str, 0).show();
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_seclreg);
        m585a();
        this.f356a.setOnClickListener(new C0089b(this));
        this.f357b.setOnClickListener(new C0090c(this));
    }
}
