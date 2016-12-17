package android.support.v7.p014a;

import android.content.Context;
import android.content.DialogInterface.OnClickListener;
import android.content.DialogInterface.OnKeyListener;
import android.graphics.drawable.Drawable;
import android.view.ContextThemeWrapper;
import android.view.View;
import android.widget.ListAdapter;

/* renamed from: android.support.v7.a.t */
public class C0230t {
    private final C0221k f840a;
    private int f841b;

    public C0230t(Context context) {
        this(context, C0229s.m1962a(context, 0));
    }

    public C0230t(Context context, int i) {
        this.f840a = new C0221k(new ContextThemeWrapper(context, C0229s.m1962a(context, i)));
        this.f841b = i;
    }

    public Context m1964a() {
        return this.f840a.f800a;
    }

    public C0230t m1965a(OnKeyListener onKeyListener) {
        this.f840a.f817r = onKeyListener;
        return this;
    }

    public C0230t m1966a(Drawable drawable) {
        this.f840a.f803d = drawable;
        return this;
    }

    public C0230t m1967a(View view) {
        this.f840a.f806g = view;
        return this;
    }

    public C0230t m1968a(ListAdapter listAdapter, OnClickListener onClickListener) {
        this.f840a.f819t = listAdapter;
        this.f840a.f820u = onClickListener;
        return this;
    }

    public C0230t m1969a(CharSequence charSequence) {
        this.f840a.f805f = charSequence;
        return this;
    }

    public C0229s m1970b() {
        C0229s c0229s = new C0229s(this.f840a.f800a, this.f841b, false);
        this.f840a.m1960a(c0229s.f839a);
        c0229s.setCancelable(this.f840a.f814o);
        if (this.f840a.f814o) {
            c0229s.setCanceledOnTouchOutside(true);
        }
        c0229s.setOnCancelListener(this.f840a.f815p);
        c0229s.setOnDismissListener(this.f840a.f816q);
        if (this.f840a.f817r != null) {
            c0229s.setOnKeyListener(this.f840a.f817r);
        }
        return c0229s;
    }
}
