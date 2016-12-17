package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bo;
import android.util.AttributeSet;
import android.widget.TextView;

public class bp extends TextView implements bo {
    private ao f908a;
    private aj f909b;
    private bn f910c;

    public bp(Context context) {
        this(context, null);
    }

    public bp(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 16842884);
    }

    public bp(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        this.f908a = ao.m2497a();
        this.f909b = new aj(this, this.f908a);
        this.f909b.m2479a(attributeSet, i);
        this.f910c = bn.m2593a((TextView) this);
        this.f910c.m2598a(attributeSet, i);
        this.f910c.m2595a();
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f909b != null) {
            this.f909b.m2482c();
        }
        if (this.f910c != null) {
            this.f910c.m2595a();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        return this.f909b != null ? this.f909b.m2474a() : null;
    }

    public Mode getSupportBackgroundTintMode() {
        return this.f909b != null ? this.f909b.m2480b() : null;
    }

    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        if (this.f909b != null) {
            this.f909b.m2478a(drawable);
        }
    }

    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        if (this.f909b != null) {
            this.f909b.m2475a(i);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        if (this.f909b != null) {
            this.f909b.m2476a(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.f909b != null) {
            this.f909b.m2477a(mode);
        }
    }

    public void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        if (this.f910c != null) {
            this.f910c.m2596a(context, i);
        }
    }
}
