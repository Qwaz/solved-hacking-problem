package android.support.v7.p014a;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.v4.p003a.C0021a;
import android.support.v4.p003a.C0045w;
import android.support.v4.p003a.bc;
import android.support.v4.p003a.bk;
import android.support.v4.p003a.bl;
import android.support.v4.p004h.C0169v;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup.LayoutParams;

/* renamed from: android.support.v7.a.u */
public class C0231u extends C0045w implements bl, C0209v {
    private C0201w f842l;
    private int f843m;
    private boolean f844n;

    public C0231u() {
        this.f843m = 0;
    }

    public Intent m1971a() {
        return bc.m256a(this);
    }

    public C0212b m1972a(C0208c c0208c) {
        return null;
    }

    public void m1973a(bk bkVar) {
        bkVar.m284a((Activity) this);
    }

    public void m1974a(C0212b c0212b) {
    }

    public boolean m1975a(Intent intent) {
        return bc.m258a((Activity) this, intent);
    }

    public void addContentView(View view, LayoutParams layoutParams) {
        m1983i().m1631b(view, layoutParams);
    }

    public void m1976b(Intent intent) {
        bc.m261b((Activity) this, intent);
    }

    public void m1977b(bk bkVar) {
    }

    public void m1978b(C0212b c0212b) {
    }

    public void m1979d() {
        m1983i().m1636e();
    }

    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        if (C0169v.m1352a(keyEvent, 4096) && keyEvent.getUnicodeChar(keyEvent.getMetaState() & -28673) == 60) {
            int action = keyEvent.getAction();
            if (action == 0) {
                C0200a f = m1980f();
                if (f != null && f.m1607b() && f.m1615g()) {
                    this.f844n = true;
                    return true;
                }
            } else if (action == 1 && this.f844n) {
                this.f844n = false;
                return true;
            }
        }
        return super.dispatchKeyEvent(keyEvent);
    }

    public C0200a m1980f() {
        return m1983i().m1621a();
    }

    public View findViewById(int i) {
        return m1983i().m1622a(i);
    }

    public boolean m1981g() {
        Intent a = m1971a();
        if (a == null) {
            return false;
        }
        if (m1975a(a)) {
            bk a2 = bk.m283a((Context) this);
            m1973a(a2);
            m1977b(a2);
            a2.m287a();
            try {
                C0021a.m76a(this);
            } catch (IllegalStateException e) {
                finish();
            }
        } else {
            m1976b(a);
        }
        return true;
    }

    public MenuInflater getMenuInflater() {
        return m1983i().m1628b();
    }

    @Deprecated
    public void m1982h() {
    }

    public C0201w m1983i() {
        if (this.f842l == null) {
            this.f842l = C0201w.m1617a((Activity) this, (C0209v) this);
        }
        return this.f842l;
    }

    public void invalidateOptionsMenu() {
        m1983i().m1636e();
    }

    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        m1983i().m1623a(configuration);
    }

    public void onContentChanged() {
        m1982h();
    }

    protected void onCreate(Bundle bundle) {
        C0201w i = m1983i();
        i.m1638g();
        i.m1624a(bundle);
        if (i.m1639h() && this.f843m != 0) {
            if (VERSION.SDK_INT >= 23) {
                onApplyThemeResource(getTheme(), this.f843m, false);
            } else {
                setTheme(this.f843m);
            }
        }
        super.onCreate(bundle);
    }

    protected void onDestroy() {
        super.onDestroy();
        m1983i().m1637f();
    }

    public final boolean onMenuItemSelected(int i, MenuItem menuItem) {
        if (super.onMenuItemSelected(i, menuItem)) {
            return true;
        }
        C0200a f = m1980f();
        return (menuItem.getItemId() != 16908332 || f == null || (f.m1599a() & 4) == 0) ? false : m1981g();
    }

    public boolean onMenuOpened(int i, Menu menu) {
        return super.onMenuOpened(i, menu);
    }

    public void onPanelClosed(int i, Menu menu) {
        super.onPanelClosed(i, menu);
    }

    protected void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        m1983i().m1630b(bundle);
    }

    protected void onPostResume() {
        super.onPostResume();
        m1983i().m1635d();
    }

    protected void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        m1983i().m1633c(bundle);
    }

    protected void onStop() {
        super.onStop();
        m1983i().m1632c();
    }

    protected void onTitleChanged(CharSequence charSequence, int i) {
        super.onTitleChanged(charSequence, i);
        m1983i().m1627a(charSequence);
    }

    public void setContentView(int i) {
        m1983i().m1629b(i);
    }

    public void setContentView(View view) {
        m1983i().m1625a(view);
    }

    public void setContentView(View view, LayoutParams layoutParams) {
        m1983i().m1626a(view, layoutParams);
    }

    public void setTheme(int i) {
        super.setTheme(i);
        this.f843m = i;
    }
}
