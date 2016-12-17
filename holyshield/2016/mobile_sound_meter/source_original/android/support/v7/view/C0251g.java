package android.support.v7.view;

import android.annotation.TargetApi;
import android.content.Context;
import android.support.v4.p008d.p009a.C0089a;
import android.support.v7.view.menu.ab;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.View;

@TargetApi(11)
/* renamed from: android.support.v7.view.g */
public class C0251g extends ActionMode {
    final Context f858a;
    final C0212b f859b;

    public C0251g(Context context, C0212b c0212b) {
        this.f858a = context;
        this.f859b = c0212b;
    }

    public void finish() {
        this.f859b.m1886c();
    }

    public View getCustomView() {
        return this.f859b.m1891i();
    }

    public Menu getMenu() {
        return ab.m2084a(this.f858a, (C0089a) this.f859b.m1883b());
    }

    public MenuInflater getMenuInflater() {
        return this.f859b.m1877a();
    }

    public CharSequence getSubtitle() {
        return this.f859b.m1889g();
    }

    public Object getTag() {
        return this.f859b.m1892j();
    }

    public CharSequence getTitle() {
        return this.f859b.m1888f();
    }

    public boolean getTitleOptionalHint() {
        return this.f859b.m1893k();
    }

    public void invalidate() {
        this.f859b.m1887d();
    }

    public boolean isTitleOptional() {
        return this.f859b.m1890h();
    }

    public void setCustomView(View view) {
        this.f859b.m1879a(view);
    }

    public void setSubtitle(int i) {
        this.f859b.m1884b(i);
    }

    public void setSubtitle(CharSequence charSequence) {
        this.f859b.m1880a(charSequence);
    }

    public void setTag(Object obj) {
        this.f859b.m1881a(obj);
    }

    public void setTitle(int i) {
        this.f859b.m1878a(i);
    }

    public void setTitle(CharSequence charSequence) {
        this.f859b.m1885b(charSequence);
    }

    public void setTitleOptionalHint(boolean z) {
        this.f859b.m1882a(z);
    }
}
