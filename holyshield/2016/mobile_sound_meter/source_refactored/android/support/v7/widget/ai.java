package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bo;
import android.support.v7.p015b.C0233b;
import android.util.AttributeSet;
import android.widget.AutoCompleteTextView;
import android.widget.TextView;

public class ai extends AutoCompleteTextView implements bo {
    private static final int[] f1181a;
    private ao f1182b;
    private aj f1183c;
    private bn f1184d;

    static {
        f1181a = new int[]{16843126};
    }

    public ai(Context context) {
        this(context, null);
    }

    public ai(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.autoCompleteTextViewStyle);
    }

    public ai(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        this.f1182b = ao.m2497a();
        dh a = dh.m2710a(getContext(), attributeSet, f1181a, i, 0);
        if (a.m2725f(0)) {
            setDropDownBackgroundDrawable(a.m2713a(0));
        }
        a.m2714a();
        this.f1183c = new aj(this, this.f1182b);
        this.f1183c.m2479a(attributeSet, i);
        this.f1184d = bn.m2593a((TextView) this);
        this.f1184d.m2598a(attributeSet, i);
        this.f1184d.m2595a();
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1183c != null) {
            this.f1183c.m2482c();
        }
        if (this.f1184d != null) {
            this.f1184d.m2595a();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        return this.f1183c != null ? this.f1183c.m2474a() : null;
    }

    public Mode getSupportBackgroundTintMode() {
        return this.f1183c != null ? this.f1183c.m2480b() : null;
    }

    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        if (this.f1183c != null) {
            this.f1183c.m2478a(drawable);
        }
    }

    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        if (this.f1183c != null) {
            this.f1183c.m2475a(i);
        }
    }

    public void setDropDownBackgroundResource(int i) {
        if (this.f1182b != null) {
            setDropDownBackgroundDrawable(this.f1182b.m2520a(getContext(), i));
        } else {
            super.setDropDownBackgroundResource(i);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        if (this.f1183c != null) {
            this.f1183c.m2476a(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.f1183c != null) {
            this.f1183c.m2477a(mode);
        }
    }

    public void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        if (this.f1184d != null) {
            this.f1184d.m2596a(context, i);
        }
    }
}
