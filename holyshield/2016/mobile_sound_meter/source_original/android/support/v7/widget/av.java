package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bo;
import android.support.v7.p015b.C0233b;
import android.util.AttributeSet;
import android.widget.ImageButton;

public class av extends ImageButton implements bo {
    private aj f1323a;
    private aw f1324b;

    public av(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.imageButtonStyle);
    }

    public av(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        ao a = ao.m2497a();
        this.f1323a = new aj(this, a);
        this.f1323a.m2479a(attributeSet, i);
        this.f1324b = new aw(this, a);
        this.f1324b.m2530a(attributeSet, i);
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1323a != null) {
            this.f1323a.m2482c();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        return this.f1323a != null ? this.f1323a.m2474a() : null;
    }

    public Mode getSupportBackgroundTintMode() {
        return this.f1323a != null ? this.f1323a.m2480b() : null;
    }

    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        if (this.f1323a != null) {
            this.f1323a.m2478a(drawable);
        }
    }

    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        if (this.f1323a != null) {
            this.f1323a.m2475a(i);
        }
    }

    public void setImageResource(int i) {
        this.f1324b.m2529a(i);
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        if (this.f1323a != null) {
            this.f1323a.m2476a(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.f1323a != null) {
            this.f1323a.m2477a(mode);
        }
    }
}
