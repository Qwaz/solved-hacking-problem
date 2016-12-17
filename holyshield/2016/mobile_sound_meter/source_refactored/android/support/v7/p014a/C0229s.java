package android.support.v7.p014a;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v7.p015b.C0233b;
import android.util.TypedValue;
import android.view.KeyEvent;

/* renamed from: android.support.v7.a.s */
public class C0229s extends as implements DialogInterface {
    private C0215e f839a;

    C0229s(Context context, int i, boolean z) {
        super(context, C0229s.m1962a(context, i));
        this.f839a = new C0215e(getContext(), this, getWindow());
    }

    static int m1962a(Context context, int i) {
        if (i >= 16777216) {
            return i;
        }
        TypedValue typedValue = new TypedValue();
        context.getTheme().resolveAttribute(C0233b.alertDialogTheme, typedValue, true);
        return typedValue.resourceId;
    }

    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.f839a.m1945a();
    }

    public boolean onKeyDown(int i, KeyEvent keyEvent) {
        return this.f839a.m1951a(i, keyEvent) ? true : super.onKeyDown(i, keyEvent);
    }

    public boolean onKeyUp(int i, KeyEvent keyEvent) {
        return this.f839a.m1955b(i, keyEvent) ? true : super.onKeyUp(i, keyEvent);
    }

    public void setTitle(CharSequence charSequence) {
        super.setTitle(charSequence);
        this.f839a.m1950a(charSequence);
    }
}
