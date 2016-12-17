package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bo;
import android.support.v7.p015b.C0233b;
import android.util.AttributeSet;
import android.widget.EditText;
import android.widget.TextView;

public class au extends EditText implements bo {
    private ao f1320a;
    private aj f1321b;
    private bn f1322c;

    public au(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.editTextStyle);
    }

    public au(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        this.f1320a = ao.m2497a();
        this.f1321b = new aj(this, this.f1320a);
        this.f1321b.m2479a(attributeSet, i);
        this.f1322c = bn.m2593a((TextView) this);
        this.f1322c.m2598a(attributeSet, i);
        this.f1322c.m2595a();
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1321b != null) {
            this.f1321b.m2482c();
        }
        if (this.f1322c != null) {
            this.f1322c.m2595a();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        return this.f1321b != null ? this.f1321b.m2474a() : null;
    }

    public Mode getSupportBackgroundTintMode() {
        return this.f1321b != null ? this.f1321b.m2480b() : null;
    }

    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        if (this.f1321b != null) {
            this.f1321b.m2478a(drawable);
        }
    }

    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        if (this.f1321b != null) {
            this.f1321b.m2475a(i);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        if (this.f1321b != null) {
            this.f1321b.m2476a(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.f1321b != null) {
            this.f1321b.m2477a(mode);
        }
    }

    public void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        if (this.f1322c != null) {
            this.f1322c.m2596a(context, i);
        }
    }
}
