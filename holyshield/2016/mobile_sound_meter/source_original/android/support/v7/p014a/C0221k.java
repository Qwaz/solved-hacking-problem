package android.support.v7.p014a;

import android.content.Context;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnDismissListener;
import android.content.DialogInterface.OnKeyListener;
import android.content.DialogInterface.OnMultiChoiceClickListener;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.SimpleCursorAdapter;

/* renamed from: android.support.v7.a.k */
public class C0221k {
    public int f787A;
    public boolean f788B;
    public boolean[] f789C;
    public boolean f790D;
    public boolean f791E;
    public int f792F;
    public OnMultiChoiceClickListener f793G;
    public Cursor f794H;
    public String f795I;
    public String f796J;
    public OnItemSelectedListener f797K;
    public C0226p f798L;
    public boolean f799M;
    public final Context f800a;
    public final LayoutInflater f801b;
    public int f802c;
    public Drawable f803d;
    public int f804e;
    public CharSequence f805f;
    public View f806g;
    public CharSequence f807h;
    public CharSequence f808i;
    public OnClickListener f809j;
    public CharSequence f810k;
    public OnClickListener f811l;
    public CharSequence f812m;
    public OnClickListener f813n;
    public boolean f814o;
    public OnCancelListener f815p;
    public OnDismissListener f816q;
    public OnKeyListener f817r;
    public CharSequence[] f818s;
    public ListAdapter f819t;
    public OnClickListener f820u;
    public int f821v;
    public View f822w;
    public int f823x;
    public int f824y;
    public int f825z;

    public C0221k(Context context) {
        this.f802c = 0;
        this.f804e = 0;
        this.f788B = false;
        this.f792F = -1;
        this.f799M = true;
        this.f800a = context;
        this.f814o = true;
        this.f801b = (LayoutInflater) context.getSystemService("layout_inflater");
    }

    private void m1959b(C0215e c0215e) {
        ListAdapter simpleCursorAdapter;
        ListView listView = (ListView) this.f801b.inflate(c0215e.f741H, null);
        if (!this.f790D) {
            int m = this.f791E ? c0215e.f743J : c0215e.f744K;
            simpleCursorAdapter = this.f794H != null ? new SimpleCursorAdapter(this.f800a, m, this.f794H, new String[]{this.f795I}, new int[]{16908308}) : this.f819t != null ? this.f819t : new C0228r(this.f800a, m, 16908308, this.f818s);
        } else if (this.f794H == null) {
            simpleCursorAdapter = new C0222l(this, this.f800a, c0215e.f742I, 16908308, this.f818s, listView);
        } else {
            Object c0223m = new C0223m(this, this.f800a, this.f794H, false, listView, c0215e);
        }
        if (this.f798L != null) {
            this.f798L.m1961a(listView);
        }
        c0215e.f737D = simpleCursorAdapter;
        c0215e.f738E = this.f792F;
        if (this.f820u != null) {
            listView.setOnItemClickListener(new C0224n(this, c0215e));
        } else if (this.f793G != null) {
            listView.setOnItemClickListener(new C0225o(this, listView, c0215e));
        }
        if (this.f797K != null) {
            listView.setOnItemSelectedListener(this.f797K);
        }
        if (this.f791E) {
            listView.setChoiceMode(1);
        } else if (this.f790D) {
            listView.setChoiceMode(2);
        }
        c0215e.f753f = listView;
    }

    public void m1960a(C0215e c0215e) {
        if (this.f806g != null) {
            c0215e.m1953b(this.f806g);
        } else {
            if (this.f805f != null) {
                c0215e.m1950a(this.f805f);
            }
            if (this.f803d != null) {
                c0215e.m1948a(this.f803d);
            }
            if (this.f802c != 0) {
                c0215e.m1952b(this.f802c);
            }
            if (this.f804e != 0) {
                c0215e.m1952b(c0215e.m1956c(this.f804e));
            }
        }
        if (this.f807h != null) {
            c0215e.m1954b(this.f807h);
        }
        if (this.f808i != null) {
            c0215e.m1947a(-1, this.f808i, this.f809j, null);
        }
        if (this.f810k != null) {
            c0215e.m1947a(-2, this.f810k, this.f811l, null);
        }
        if (this.f812m != null) {
            c0215e.m1947a(-3, this.f812m, this.f813n, null);
        }
        if (!(this.f818s == null && this.f794H == null && this.f819t == null)) {
            m1959b(c0215e);
        }
        if (this.f822w != null) {
            if (this.f788B) {
                c0215e.m1949a(this.f822w, this.f823x, this.f824y, this.f825z, this.f787A);
                return;
            }
            c0215e.m1957c(this.f822w);
        } else if (this.f821v != 0) {
            c0215e.m1946a(this.f821v);
        }
    }
}
