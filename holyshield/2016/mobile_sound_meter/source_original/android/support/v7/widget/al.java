package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.support.v4.p002b.C0020a;
import android.support.v4.widget.ba;
import android.support.v7.p015b.C0233b;
import android.util.AttributeSet;
import android.widget.CheckBox;

public class al extends CheckBox implements ba {
    private ao f1293a;
    private an f1294b;

    public al(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.checkboxStyle);
    }

    public al(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        this.f1293a = ao.m2497a();
        this.f1294b = new an(this, this.f1293a);
        this.f1294b.m2487a(attributeSet, i);
    }

    public int getCompoundPaddingLeft() {
        int compoundPaddingLeft = super.getCompoundPaddingLeft();
        return this.f1294b != null ? this.f1294b.m2483a(compoundPaddingLeft) : compoundPaddingLeft;
    }

    public ColorStateList getSupportButtonTintList() {
        return this.f1294b != null ? this.f1294b.m2484a() : null;
    }

    public Mode getSupportButtonTintMode() {
        return this.f1294b != null ? this.f1294b.m2488b() : null;
    }

    public void setButtonDrawable(int i) {
        setButtonDrawable(this.f1293a != null ? this.f1293a.m2520a(getContext(), i) : C0020a.m74a(getContext(), i));
    }

    public void setButtonDrawable(Drawable drawable) {
        super.setButtonDrawable(drawable);
        if (this.f1294b != null) {
            this.f1294b.m2489c();
        }
    }

    public void setSupportButtonTintList(ColorStateList colorStateList) {
        if (this.f1294b != null) {
            this.f1294b.m2485a(colorStateList);
        }
    }

    public void setSupportButtonTintMode(Mode mode) {
        if (this.f1294b != null) {
            this.f1294b.m2486a(mode);
        }
    }
}
