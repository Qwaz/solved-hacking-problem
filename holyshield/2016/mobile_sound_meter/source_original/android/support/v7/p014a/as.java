package android.support.v7.p014a;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.support.v7.p015b.C0233b;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup.LayoutParams;

/* renamed from: android.support.v7.a.as */
public class as extends Dialog implements C0209v {
    private C0201w f655a;

    public as(Context context, int i) {
        super(context, as.m1779a(context, i));
        m1780a().m1624a(null);
        m1780a().m1639h();
    }

    private static int m1779a(Context context, int i) {
        if (i != 0) {
            return i;
        }
        TypedValue typedValue = new TypedValue();
        context.getTheme().resolveAttribute(C0233b.dialogTheme, typedValue, true);
        return typedValue.resourceId;
    }

    public C0201w m1780a() {
        if (this.f655a == null) {
            this.f655a = C0201w.m1618a((Dialog) this, (C0209v) this);
        }
        return this.f655a;
    }

    public C0212b m1781a(C0208c c0208c) {
        return null;
    }

    public void m1782a(C0212b c0212b) {
    }

    public boolean m1783a(int i) {
        return m1780a().m1634c(i);
    }

    public void addContentView(View view, LayoutParams layoutParams) {
        m1780a().m1631b(view, layoutParams);
    }

    public void m1784b(C0212b c0212b) {
    }

    public View findViewById(int i) {
        return m1780a().m1622a(i);
    }

    public void invalidateOptionsMenu() {
        m1780a().m1636e();
    }

    protected void onCreate(Bundle bundle) {
        m1780a().m1638g();
        super.onCreate(bundle);
        m1780a().m1624a(bundle);
    }

    protected void onStop() {
        super.onStop();
        m1780a().m1632c();
    }

    public void setContentView(int i) {
        m1780a().m1629b(i);
    }

    public void setContentView(View view) {
        m1780a().m1625a(view);
    }

    public void setContentView(View view, LayoutParams layoutParams) {
        m1780a().m1626a(view, layoutParams);
    }

    public void setTitle(int i) {
        super.setTitle(i);
        m1780a().m1627a(getContext().getString(i));
    }

    public void setTitle(CharSequence charSequence) {
        super.setTitle(charSequence);
        m1780a().m1627a(charSequence);
    }
}
